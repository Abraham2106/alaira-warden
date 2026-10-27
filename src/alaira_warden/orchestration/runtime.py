"""One bounded stage per dispatch, with persistent quotas and per-run exclusion.

Trusted handlers must honor deadline/cancellation and the stable idempotency key.
At-least-once execution after a process crash is deliberate: never publish a PR here.
"""

import hashlib
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, TypedDict
from uuid import UUID, uuid4

from langgraph.graph import END, START, StateGraph
from opentelemetry import trace
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field, model_validator

from alaira_warden.config import Settings
from alaira_warden.db import connect
from alaira_warden.orchestration.checkpoints import (
    checkpoint_connection,
    saver,
    verify_checkpoints,
)

STAGES = ("inventory", "sources", "correlation")
TERMINAL = {"cancelled", "budget_exhausted", "awaiting_review"}
tracer = trace.get_tracer(__name__)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    application_id: UUID
    investigation_id: UUID
    request_key: UUID
    subject_id: str = Field(min_length=1, max_length=128)
    max_attempts: int = Field(default=9, ge=1, le=30)
    max_active_seconds: int = Field(default=180, ge=1, le=1800)
    stage_seconds: int = Field(default=30, ge=1, le=120)
    snapshot_id: UUID | None = None
    advisory_identifier: str | None = Field(default=None, max_length=100)
    data_mode: Literal["local", "zetaris"] = "local"

    @model_validator(mode="after")
    def stage_fits_budget(self):
        if self.stage_seconds > self.max_active_seconds:
            raise ValueError("A stage reservation must fit within the active time budget")
        return self


class StageOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["ready", "blocked", "retryable"]
    # Only persisted evidence identifiers enter checkpoints, never tokens or raw responses.
    references: tuple[UUID, ...] = Field(default=(), max_length=1000)
    reason: Literal["none", "incomplete", "unavailable", "unsupported"] = "none"


class RunState(TypedDict):
    run_id: str
    stage: int
    status: str
    references: dict[str, list[str]]
    reason: str


@dataclass(frozen=True)
class StageContext:
    run_id: UUID
    application_id: UUID
    investigation_id: UUID
    subject_id: str
    idempotency_key: str
    deadline: float
    cancelled: Callable[[], bool]
    references: Mapping[str, tuple[str, ...]]
    snapshot_id: UUID | None = None
    advisory_identifier: str | None = None
    data_mode: str = "local"


class RunBusy(RuntimeError):
    pass


class WorkflowRuntime:
    def __init__(self, settings: Settings, handlers: Mapping[str, Callable]):
        if set(handlers) - set(STAGES):
            raise ValueError("Unknown workflow stage")
        self.settings = settings
        self.handlers = dict(handlers)

    def start(self, request: RunRequest) -> UUID:
        encoded = request.model_dump_json()
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        identifier = uuid4()
        with connect(self.settings) as connection:
            case = connection.execute(
                "SELECT application_id FROM investigations WHERE id = %s",
                (request.investigation_id,),
            ).fetchone()
            if not case or case["application_id"] != request.application_id:
                raise ValueError("Investigation is outside the requested application")
            row = connection.execute(
                "INSERT INTO workflow_runs "
                "(id, investigation_id, actor, request_key, request_hash, status, stage, "
                "state, max_attempts, max_active_seconds) "
                "VALUES (%s,%s,%s,%s,%s,'queued','inventory',%s,%s,%s) "
                "ON CONFLICT (investigation_id, request_key) DO NOTHING RETURNING id",
                (
                    identifier,
                    request.investigation_id,
                    request.subject_id,
                    request.request_key,
                    digest,
                    Jsonb(json.loads(encoded)),
                    request.max_attempts,
                    request.max_active_seconds,
                ),
            ).fetchone()
            if row:
                self._audit(connection, identifier, request.subject_id, "workflow.created")
                return identifier
            existing = connection.execute(
                "SELECT id, request_hash FROM workflow_runs "
                "WHERE investigation_id = %s AND request_key = %s",
                (request.investigation_id, request.request_key),
            ).fetchone()
            if existing["request_hash"] != digest:
                raise ValueError("Idempotency key was reused with different input")
            return existing["id"]

    @staticmethod
    def _audit(connection, identifier: UUID, actor: str, action: str) -> None:
        connection.execute(
            "INSERT INTO audit_events(entity_id, actor, action) VALUES (%s,%s,%s)",
            (identifier, actor, action),
        )

    def control(
        self,
        identifier: UUID,
        application_id: UUID,
        actor: str,
        action: Literal["pause", "resume", "cancel"],
    ) -> None:
        if action not in {"pause", "resume", "cancel"} or not actor or len(actor) > 128:
            raise ValueError("Invalid workflow control")
        with connect(self.settings) as connection:
            row = connection.execute(
                "SELECT w.id FROM workflow_runs w JOIN investigations i "
                "ON i.id = w.investigation_id WHERE w.id = %s AND i.application_id = %s "
                "FOR UPDATE OF w",
                (identifier, application_id),
            ).fetchone()
            if not row:
                raise ValueError("Workflow outside the requested application")
            connection.execute(
                "UPDATE workflow_runs SET pause_requested = %s, "
                "cancel_requested = cancel_requested OR %s, updated_at = now() WHERE id = %s",
                (action == "pause", action == "cancel", identifier),
            )
            self._audit(connection, identifier, actor, f"workflow.{action}_requested")

    def _row(self, identifier: UUID) -> dict:
        with connect(self.settings) as connection:
            row = connection.execute(
                "SELECT * FROM workflow_runs WHERE id = %s", (identifier,)
            ).fetchone()
            if row is None or row["actor"] is None:
                raise ValueError("Workflow missing or from an unsupported legacy version")
            return row

    def advance(self, identifier: UUID, application_id: UUID) -> RunState:
        # Session lock spans all checkpoint transactions. Other runs are independent.
        key = int.from_bytes(hashlib.sha256(identifier.bytes).digest()[:8], "big", signed=True)
        with checkpoint_connection(self.settings) as connection:
            verify_checkpoints(connection)
            if not connection.execute(
                "SELECT pg_try_advisory_lock(%s) AS acquired", (key,)
            ).fetchone()["acquired"]:
                raise RunBusy("Another worker holds this run")
            try:
                row = self._row(identifier)
                request = RunRequest.model_validate(row["state"])
                if request.application_id != application_id:
                    raise ValueError("Workflow outside the requested application")
                graph = StateGraph(RunState)
                graph.add_node("step", lambda state: self._step(state, request))
                graph.add_edge(START, "step")
                graph.add_edge("step", END)
                compiled = graph.compile(checkpointer=saver(connection))
                config = {"configurable": {"thread_id": str(identifier)}}
                checkpoint = compiled.get_state(config)
                state = checkpoint.values or RunState(
                    run_id=str(identifier), stage=0, status="queued", references={}, reason="none"
                )
                if state["status"] not in TERMINAL:
                    # Input is the persisted state, never a caller-supplied stage or outcome.
                    state = compiled.invoke(state, config, durability="sync")
                with connect(self.settings) as ledger:
                    ledger.execute(
                        "UPDATE workflow_runs SET status=%s, stage=%s, updated_at=now() "
                        "WHERE id=%s",
                        (state["status"], self._stage_name(state["stage"]), identifier),
                    )
                return state
            finally:
                connection.execute("SELECT pg_advisory_unlock(%s)", (key,))

    @staticmethod
    def _stage_name(index: int) -> str:
        return STAGES[index] if index < len(STAGES) else "review"

    def _step(self, state: RunState, request: RunRequest) -> RunState:
        identifier = UUID(state["run_id"])
        row = self._row(identifier)
        if row["cancel_requested"]:
            return {**state, "status": "cancelled", "reason": "cancel_requested"}
        if row["pause_requested"]:
            return {**state, "status": "paused", "reason": "pause_requested"}
        stage = self._stage_name(state["stage"])
        if stage not in self.handlers:
            return {**state, "status": "requires_intervention", "reason": "handler_unavailable"}
        reservation = request.stage_seconds * 1000
        with connect(self.settings) as connection:
            charged = connection.execute(
                "UPDATE workflow_runs SET attempts=attempts+1, reserved_ms=reserved_ms+%s, "
                "updated_at=now() WHERE id=%s AND attempts < max_attempts "
                "AND reserved_ms+%s <= max_active_seconds*1000 RETURNING id",
                (reservation, identifier, reservation),
            ).fetchone()
            if not charged:
                return {**state, "status": "budget_exhausted", "reason": "quota_exhausted"}
            self._audit(connection, identifier, request.subject_id, f"workflow.{stage}.started")
        started = time.monotonic()
        deadline = started + request.stage_seconds

        def cancelled() -> bool:
            controls = self._row(identifier)
            return controls["cancel_requested"] or time.monotonic() >= deadline

        context = StageContext(
            identifier,
            request.application_id,
            request.investigation_id,
            request.subject_id,
            f"{identifier}:{stage}:v1",
            deadline,
            cancelled,
            MappingProxyType({key: tuple(value) for key, value in state["references"].items()}),
            request.snapshot_id,
            request.advisory_identifier,
            request.data_mode,
        )
        with tracer.start_as_current_span(f"workflow.{stage}") as span:
            span.set_attribute("warden.run_id", str(identifier))
            span.set_attribute("warden.case_id", str(request.investigation_id))
            try:
                output = StageOutput.model_validate(self.handlers[stage](context))
            except Exception:
                # Private provider errors, repository text and credentials must not enter state.
                output = StageOutput(status="retryable", reason="unavailable")
            elapsed = max(1, int((time.monotonic() - started) * 1000))
            with connect(self.settings) as connection:
                connection.execute(
                    "UPDATE workflow_runs SET reserved_ms=reserved_ms-%s+%s WHERE id=%s",
                    (reservation, elapsed, identifier),
                )
                self._audit(
                    connection, identifier, request.subject_id, f"workflow.{stage}.{output.status}"
                )
            controls = self._row(identifier)
            if controls["cancel_requested"]:
                return {**state, "status": "cancelled", "reason": "cancel_requested"}
            if (
                elapsed >= reservation
                or controls["reserved_ms"] >= request.max_active_seconds * 1000
            ):
                return {**state, "status": "budget_exhausted", "reason": "deadline_exceeded"}
            if output.status != "ready" or not output.references:
                return {
                    **state,
                    "status": "requires_intervention",
                    "reason": "incomplete" if output.status == "ready" else output.reason,
                }
            index = state["stage"] + 1
            return {
                **state,
                "stage": index,
                "status": "awaiting_review" if index == len(STAGES) else "running",
                "references": {**state["references"], stage: list(map(str, output.references))},
                "reason": "none",
            }
