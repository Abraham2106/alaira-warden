"""Durability checks with real PostgreSQL and the effective runtime database role."""

import os
import time
from contextlib import contextmanager
from threading import Event, Thread
from uuid import uuid4

import pytest
from psycopg.conninfo import conninfo_to_dict
from psycopg.errors import InsufficientPrivilege

from alaira_warden.config import Settings
from alaira_warden.db import connect, migrate
from alaira_warden.orchestration.checkpoints import (
    checkpoint_connection,
    setup_checkpoints,
    verify_checkpoints,
)
from alaira_warden.orchestration.runtime import (
    RunBusy,
    RunRequest,
    StageOutput,
    WorkflowRuntime,
)

pytestmark = pytest.mark.skipif(
    not os.getenv("WARDEN_TEST_DATABASE_URL"), reason="No isolated PostgreSQL configured"
)


@pytest.fixture
def runtime(monkeypatch):
    url = os.environ["WARDEN_TEST_DATABASE_URL"]
    assert conninfo_to_dict(url).get("dbname", "").endswith("_test")
    settings = Settings(_env_file=None, warden_database_url=url)
    with connect(settings) as connection:
        if not connection.execute("SELECT 1 FROM pg_roles WHERE rolname='warden_app'").fetchone():
            connection.execute("CREATE ROLE warden_app NOLOGIN")
    migrate(settings=settings)
    setup_checkpoints(settings)

    @contextmanager
    def domain(runtime_settings):
        with connect(runtime_settings) as connection:
            connection.execute("SET LOCAL ROLE warden_app")
            yield connection

    @contextmanager
    def checkpoints(runtime_settings):
        with checkpoint_connection(runtime_settings) as connection:
            connection.execute("SET ROLE warden_app")
            yield connection

    monkeypatch.setattr("alaira_warden.orchestration.runtime.connect", domain)
    monkeypatch.setattr("alaira_warden.orchestration.runtime.checkpoint_connection", checkpoints)
    app_id, case_id = uuid4(), uuid4()
    with domain(settings) as connection:
        connection.execute(
            "INSERT INTO applications(id,name,repository) VALUES (%s,'Synthetic','test/repo')",
            (app_id,),
        )
        connection.execute(
            "INSERT INTO investigations(id,application_id,title,source_url,description) "
            "VALUES (%s,%s,'Synthetic','https://example.com','No real vulnerability')",
            (case_id, app_id),
        )
    request = RunRequest(
        application_id=app_id,
        investigation_id=case_id,
        request_key=uuid4(),
        subject_id="test-analyst",
    )
    return settings, request, domain, checkpoints


def test_restart_recovers_checkpoints_and_does_not_repeat_completed_stage(runtime):
    settings, request, _, _ = runtime
    calls = []

    def handler(context):
        calls.append(context.idempotency_key)
        assert context.subject_id == request.subject_id
        assert not context.cancelled()
        return StageOutput(status="ready", references=(uuid4(),))

    handlers = dict.fromkeys(("inventory", "sources", "correlation"), handler)
    worker = WorkflowRuntime(settings, handlers)
    identifier = worker.start(request)
    assert worker.start(request) == identifier
    assert worker.advance(identifier, request.application_id)["stage"] == 1
    restarted = WorkflowRuntime(settings, handlers)
    assert restarted.advance(identifier, request.application_id)["stage"] == 2
    final = restarted.advance(identifier, request.application_id)
    assert final["status"] == "awaiting_review"
    assert final["stage"] == 3
    assert restarted.advance(identifier, request.application_id) == final
    assert len(calls) == len(set(calls)) == 3


def test_scope_and_idempotency_conflicts_are_rejected(runtime):
    settings, request, _, _ = runtime
    worker = WorkflowRuntime(settings, {})
    identifier = worker.start(request)
    with pytest.raises(ValueError, match="different input"):
        worker.start(request.model_copy(update={"subject_id": "other"}))
    with pytest.raises(ValueError, match="outside"):
        worker.start(request.model_copy(update={"application_id": uuid4()}))
    with pytest.raises(ValueError, match="outside"):
        worker.advance(identifier, uuid4())
    with pytest.raises(ValueError, match="outside"):
        worker.control(identifier, uuid4(), "test-actor", "cancel")


def test_missing_handler_does_not_fabricate_evidence_or_consume_attempt(runtime):
    settings, request, domain, _ = runtime
    worker = WorkflowRuntime(settings, {})
    identifier = worker.start(request)
    result = worker.advance(identifier, request.application_id)
    assert result["status"] == "requires_intervention"
    assert result["references"] == {}
    with domain(settings) as connection:
        assert (
            connection.execute(
                "SELECT attempts FROM workflow_runs WHERE id=%s", (identifier,)
            ).fetchone()["attempts"]
            == 0
        )


def test_pause_resume_and_irreversible_cancel_survive_new_worker(runtime):
    settings, request, _, _ = runtime
    worker = WorkflowRuntime(settings, {})
    identifier = worker.start(request)
    worker.control(identifier, request.application_id, "reviewer", "pause")
    assert worker.advance(identifier, request.application_id)["status"] == "paused"
    worker.control(identifier, request.application_id, "reviewer", "resume")
    assert worker.advance(identifier, request.application_id)["status"] == "requires_intervention"
    worker.control(identifier, request.application_id, "reviewer", "cancel")
    worker.control(identifier, request.application_id, "reviewer", "resume")
    restarted = WorkflowRuntime(settings, {})
    assert restarted.advance(identifier, request.application_id)["status"] == "cancelled"


def test_attempt_budget_survives_failures_and_error_text_is_redacted(runtime):
    settings, request, domain, _ = runtime
    request = request.model_copy(update={"max_attempts": 2})
    keys = []

    def failing(context):
        keys.append(context.idempotency_key)
        raise RuntimeError("token=private-secret")

    worker = WorkflowRuntime(settings, {"inventory": failing})
    identifier = worker.start(request)
    for _ in range(2):
        result = worker.advance(identifier, request.application_id)
        assert result["status"] == "requires_intervention"
        assert "private-secret" not in str(result)
    assert worker.advance(identifier, request.application_id)["status"] == "budget_exhausted"
    assert len(keys) == 2 and keys[0] == keys[1]
    with domain(settings) as connection:
        assert (
            connection.execute(
                "SELECT attempts FROM workflow_runs WHERE id=%s", (identifier,)
            ).fetchone()["attempts"]
            == 2
        )


def test_unreturned_time_reservation_is_not_reset_after_crash(runtime):
    settings, request, domain, _ = runtime
    worker = WorkflowRuntime(settings, {})
    identifier = worker.start(request)
    # Simulate a process killed after charging its time reservation, before refund/checkpoint.
    with domain(settings) as connection:
        connection.execute(
            "UPDATE workflow_runs SET reserved_ms=max_active_seconds*1000 WHERE id=%s",
            (identifier,),
        )
    restarted = WorkflowRuntime(
        settings, {"inventory": lambda _: StageOutput(status="ready", references=(uuid4(),))}
    )
    assert restarted.advance(identifier, request.application_id)["status"] == "budget_exhausted"


def test_exclusion_and_cooperative_cancel_while_handler_is_running(runtime):
    settings, request, _, _ = runtime
    entered, release = Event(), Event()
    results = []

    def handler(context):
        entered.set()
        assert release.wait(10)
        assert context.cancelled()
        return StageOutput(status="ready", references=(uuid4(),))

    worker = WorkflowRuntime(settings, {"inventory": handler})
    identifier = worker.start(request)
    thread = Thread(
        target=lambda: results.append(worker.advance(identifier, request.application_id))
    )
    thread.start()
    try:
        assert entered.wait(10)
        with pytest.raises(RunBusy):
            WorkflowRuntime(settings, {}).advance(identifier, request.application_id)
        worker.control(identifier, request.application_id, "reviewer", "cancel")
    finally:
        release.set()
        thread.join(10)
    assert not thread.is_alive()
    assert results[0]["status"] == "cancelled"
    assert results[0]["references"] == {}


def test_runtime_cannot_migrate_checkpoints_or_rewrite_audit(runtime):
    settings, _, _, checkpoints = runtime
    with checkpoints(settings) as connection:
        verify_checkpoints(connection)
        with pytest.raises(InsufficientPrivilege):
            connection.execute("CREATE TABLE warden_workflow.forbidden(id integer)")
        with pytest.raises(InsufficientPrivilege):
            connection.execute("DELETE FROM checkpoint_migrations")


def test_late_handler_result_is_discarded(runtime):
    settings, request, _, _ = runtime
    request = request.model_copy(update={"stage_seconds": 1})

    def late(_):
        time.sleep(1.05)
        return StageOutput(status="ready", references=(uuid4(),))

    worker = WorkflowRuntime(settings, {"inventory": late})
    result = worker.advance(worker.start(request), request.application_id)
    assert result["status"] == "budget_exhausted"
    assert result["references"] == {}
    assert result["stage"] == 0


def test_ready_without_evidence_is_incomplete(runtime):
    settings, request, _, _ = runtime
    worker = WorkflowRuntime(settings, {"inventory": lambda _: StageOutput(status="ready")})
    result = worker.advance(worker.start(request), request.application_id)
    assert result["status"] == "requires_intervention"
    assert result["reason"] == "incomplete"
    assert result["stage"] == 0
