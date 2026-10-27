from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from alaira_warden.inventory import (
    AuthorizedApplication,
    DeploymentRecord,
    InventoryError,
    append_deployments,
    import_deployments,
    insert_snapshot,
    parse_deployment_document,
    registration_gaps,
    retire_deployment,
    snapshot_from_manifests,
)
from alaira_warden.inventory.deployments import KnownSnapshot
from alaira_warden.inventory.persist import INSERT_SNAPSHOT, RETIRE_DEPLOYMENT

OBSERVED = datetime(2026, 1, 1, tzinfo=UTC)
SHA = "c" * 40
OTHER_SHA = "d" * 40


def application(application_id: UUID | None = None) -> AuthorizedApplication:
    return AuthorizedApplication(
        application_id=application_id or uuid4(),
        repository="octo/registry-app",
        environments=("production", "staging"),
        owner="ada",
        criticality="high",
    )


def record(app: AuthorizedApplication, **overrides) -> dict:
    payload = {
        "application_id": str(app.application_id),
        "environment": "production",
        "artifact_ref": "registry.example/app@sha256:abc",
        "commit_sha": SHA,
        "deployed_at": "2024-01-01T02:00:00+02:00",
        "retired_at": "2024-06-01T00:00:00Z",
        "source_reference": "change-ticket:CHG-1",
    }
    payload.update(overrides)
    return payload


class Result:
    def __init__(self, row=None, rows=None):
        self.row = row
        self.rows = rows if rows is not None else ([] if row is None else [row])

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class Connection:
    def __init__(self, app: AuthorizedApplication):
        self.application = {"id": app.application_id, "repository": app.repository}
        self.snapshots = {}
        self.components = []
        self.deployments = {}
        self.audit = []
        self.statements = []

    def execute(self, sql, params=None):
        text = " ".join(sql.split())
        self.statements.append(text)
        if "DELETE" in text or "TRUNCATE" in text:
            raise AssertionError(text)
        if text.startswith("SELECT id, repository FROM applications"):
            row = self.application if params[0] == self.application["id"] else None
            return Result(row)
        if text.startswith("INSERT INTO inventory_snapshots"):
            snapshot_id = params[0]
            self.snapshots[snapshot_id] = {
                "id": snapshot_id,
                "application_id": params[1],
                "commit_ref": params[2],
                "tool_name": params[3],
                "tool_version": params[4],
                "completeness": params[5],
                "artifact_path": params[6],
                "observed_at": params[7],
                "warnings": params[8],
                "artifact_hash": params[9],
                "metadata": params[10],
            }
            return Result({"id": snapshot_id})
        if text.startswith("INSERT INTO components"):
            self.components.append(params)
            return Result(None)
        if text.startswith("SELECT id, application_id, commit_ref FROM inventory_snapshots"):
            return Result(self.snapshots.get(params[0]))
        if text.startswith("INSERT INTO deployments"):
            deployment_id = params[0]
            self.deployments[deployment_id] = {
                "id": deployment_id,
                "application_id": params[1],
                "snapshot_id": params[2],
                "environment": params[3],
                "artifact_ref": params[4],
                "source_reference": params[5],
                "deployed_at": params[6],
                "retired_at": params[7],
                "commit_sha": params[8],
            }
            return Result({"id": deployment_id})
        if text.startswith("SELECT id, application_id, deployed_at"):
            row = self.deployments.get(params[0])
            return Result(row)
        if text.startswith("UPDATE deployments SET retired_at"):
            row = self.deployments[params[1]]
            row["retired_at"] = params[0]
            return Result(None)
        if text.startswith("INSERT INTO audit_events"):
            self.audit.append(params)
            return Result(None)
        raise AssertionError(text)


def test_import_keeps_history_and_rejects_bad_records():
    app = application()
    other = application()
    snapshot_id = uuid4()
    known = [
        KnownSnapshot(
            snapshot_id=snapshot_id,
            application_id=app.application_id,
            commit_sha=SHA,
        )
    ]
    first = parse_deployment_document(
        {"schema_version": 1, "deployments": [record(app)]},
        application=app,
    )
    second = parse_deployment_document(
        {
            "schema_version": 1,
            "deployments": [
                record(
                    app,
                    artifact_ref="registry.example/app@sha256:def",
                    commit_sha=None,
                    snapshot_id=str(snapshot_id),
                    deployed_at="2025-01-01T00:00:00Z",
                    retired_at=None,
                    source_reference="change-ticket:CHG-2",
                )
            ],
        },
        application=app,
        snapshots=known,
    )
    combined = append_deployments(first, second)
    assert len(combined) == 2
    assert combined[0].deployed_at == datetime(2024, 1, 1, tzinfo=UTC)
    assert combined[0].execution_evidence == "not_asserted"
    assert combined[1].snapshot_id == snapshot_id
    assert "code_executed" not in combined[0].model_dump()

    with pytest.raises(InventoryError) as invalid_date:
        parse_deployment_document(
            {"schema_version": 1, "deployments": [record(app, deployed_at="yesterday")]},
            application=app,
        )
    assert invalid_date.value.category == "invalid_response"

    with pytest.raises(InventoryError) as other_app:
        parse_deployment_document(
            {"schema_version": 1, "deployments": [record(other)]},
            application=app,
        )
    assert other_app.value.category == "forbidden"

    with pytest.raises(InventoryError):
        parse_deployment_document(
            {"schema_version": 1, "deployments": [record(app, environment="lab")]},
            application=app,
        )
    with pytest.raises(InventoryError) as claimed:
        parse_deployment_document(
            {
                "schema_version": 1,
                "deployments": [record(app, code_executed=True)],
            },
            application=app,
        )
    assert claimed.value.category == "invalid_response"


def test_persistence_appends_snapshots_and_deployments_without_delete():
    app = application()
    connection = Connection(app)
    package = '{"name":"registry-app","dependencies":{"left-pad":"^1.0.0"}}'
    lock = (FIXTURE_LOCK).read_text(encoding="utf-8")
    first = snapshot_from_manifests(
        application=app,
        commit_sha=SHA,
        observed_at=OBSERVED,
        package_json_text=package,
        package_lock_text=lock,
    )
    second = snapshot_from_manifests(
        application=app,
        commit_sha=OTHER_SHA,
        observed_at=OBSERVED + timedelta(days=1),
        package_json_text=package,
        package_lock_text=lock,
    )
    first_id = insert_snapshot(connection, first, actor="ada")
    second_id = insert_snapshot(connection, second, actor="ada")
    assert first_id != second_id
    assert {row["commit_ref"] for row in connection.snapshots.values()} == {SHA, OTHER_SHA}
    assert not any("DELETE" in statement for statement in connection.statements)
    assert "octo" not in INSERT_SNAPSHOT

    imported = import_deployments(
        connection,
        {
            "schema_version": 1,
            "deployments": [
                record(app),
                record(
                    app,
                    artifact_ref="registry.example/app@sha256:next",
                    source_reference="change-ticket:CHG-2",
                    deployed_at="2025-01-01T00:00:00Z",
                    retired_at=None,
                    commit_sha=OTHER_SHA,
                ),
            ],
        },
        application=app,
        actor="ada",
    )
    assert len(imported) == 2
    assert len(connection.deployments) == 2
    older = next(row for row in connection.deployments.values() if row["commit_sha"] == SHA)
    assert older["retired_at"] == datetime(2024, 6, 1, tzinfo=UTC)

    foreign = Connection(app)
    foreign.snapshots[uuid4()] = {
        "id": uuid4(),
        "application_id": uuid4(),
        "commit_ref": SHA,
    }
    foreign_id = next(iter(foreign.snapshots))
    with pytest.raises(InventoryError) as mismatch:
        import_deployments(
            foreign,
            {
                "schema_version": 1,
                "deployments": [record(app, snapshot_id=str(foreign_id), commit_sha=SHA)],
            },
            application=app,
            snapshots=[
                KnownSnapshot(
                    snapshot_id=foreign_id,
                    application_id=app.application_id,
                    commit_sha=SHA,
                )
            ],
            actor="ada",
        )
    assert mismatch.value.category == "forbidden"
    assert foreign.deployments == {}

    deployment_id = imported[1]
    retire_deployment(
        connection,
        deployment_id,
        application_id=app.application_id,
        retired_at=datetime(2025, 2, 1, tzinfo=UTC),
        actor="ada",
    )
    assert connection.deployments[imported[0]]["artifact_ref"] == "registry.example/app@sha256:abc"
    assert connection.deployments[deployment_id]["retired_at"] == datetime(2025, 2, 1, tzinfo=UTC)
    assert RETIRE_DEPLOYMENT.startswith("UPDATE deployments SET retired_at")
    gaps = registration_gaps(
        AuthorizedApplication(application_id=app.application_id, repository=app.repository)
    )
    assert gaps == ["owner", "criticality", "environments"]


def test_deployment_requires_commit_or_snapshot():
    app = application()
    with pytest.raises(InventoryError):
        parse_deployment_document(
            {
                "schema_version": 1,
                "deployments": [record(app, commit_sha=None)],
            },
            application=app,
        )
    built = DeploymentRecord(
        application_id=app.application_id,
        environment="staging",
        artifact_ref="artifact",
        commit_sha=SHA,
        deployed_at=OBSERVED,
        source_reference="source",
    )
    assert built.execution_evidence == "not_asserted"


FIXTURE_LOCK = Path(__file__).parent / "fixtures" / "registry_app" / "package-lock.json"
