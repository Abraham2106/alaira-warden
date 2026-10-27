"""Transactional writes for the integrator's existing connection.

The caller owns the transaction. These statements insert snapshots and
deployments and never delete them. Mount them only after the SQL in
docs/handoffs/inventory.md. `commit_ref` stores the immutable commit sha.
"""

import json
from typing import Protocol
from uuid import UUID, uuid4

from alaira_warden.inventory.deployments import parse_deployment_document
from alaira_warden.inventory.errors import InventoryError
from alaira_warden.inventory.models import (
    AuthorizedApplication,
    DeploymentRecord,
    InventorySnapshot,
)

SELECT_APPLICATION = "SELECT id, repository FROM applications WHERE id = %s"
INSERT_SNAPSHOT = (
    "INSERT INTO inventory_snapshots "
    "(id, application_id, commit_ref, tool_name, tool_version, completeness, "
    "artifact_path, observed_at, warnings, artifact_hash, metadata) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s::jsonb) "
    "RETURNING id"
)
INSERT_COMPONENT = (
    "INSERT INTO components "
    "(id, snapshot_id, name, ecosystem, resolved_version, direct, dependency_paths, metadata) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)"
)
INSERT_DEPLOYMENT = (
    "INSERT INTO deployments "
    "(id, application_id, snapshot_id, environment, artifact_ref, source_reference, "
    "deployed_at, retired_at, commit_sha) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
    "RETURNING id"
)
SELECT_SNAPSHOT_OWNER = (
    "SELECT id, application_id, commit_ref FROM inventory_snapshots WHERE id = %s"
)
SELECT_DEPLOYMENT = (
    "SELECT id, application_id, deployed_at, retired_at FROM deployments WHERE id = %s"
)
RETIRE_DEPLOYMENT = (
    "UPDATE deployments SET retired_at = %s "
    "WHERE id = %s AND application_id = %s AND retired_at IS NULL"
)
INSERT_AUDIT = "INSERT INTO audit_events (entity_id, actor, action) VALUES (%s, %s, %s)"
LIST_SNAPSHOTS = (
    "SELECT id, application_id, commit_ref, tool_name, tool_version, completeness, "
    "artifact_path, observed_at, warnings, artifact_hash, metadata "
    "FROM inventory_snapshots WHERE application_id = %s "
    "ORDER BY observed_at ASC, id ASC"
)


class SQLConnection(Protocol):
    def execute(self, query: str, params: tuple | None = None): ...


def insert_snapshot(connection: SQLConnection, snapshot: InventorySnapshot, *, actor: str) -> UUID:
    actor = _actor(actor)
    application = _one(connection, SELECT_APPLICATION, (snapshot.application_id,))
    if application is None:
        raise InventoryError("forbidden", "Application was not found")
    if application["repository"] != snapshot.repository:
        raise InventoryError("forbidden", "Snapshot repository does not match the application")
    snapshot_id = uuid4()
    _one(
        connection,
        INSERT_SNAPSHOT,
        (
            snapshot_id,
            snapshot.application_id,
            snapshot.commit_sha,
            snapshot.tool_name,
            snapshot.tool_version,
            snapshot.completeness,
            snapshot.artifact_path,
            snapshot.observed_at,
            _json([warning.model_dump(mode="json") for warning in snapshot.warnings]),
            snapshot.artifact_hash,
            _json(snapshot.metadata),
        ),
    )
    for component in snapshot.components:
        connection.execute(
            INSERT_COMPONENT,
            (
                uuid4(),
                snapshot_id,
                component.name,
                component.ecosystem,
                component.resolved_version,
                component.direct,
                _json(component.dependency_paths),
                _json(component.metadata),
            ),
        )
    connection.execute(INSERT_AUDIT, (snapshot_id, actor, "inventory.snapshot_recorded"))
    return snapshot_id


def insert_deployment(connection: SQLConnection, record: DeploymentRecord, *, actor: str) -> UUID:
    actor = _actor(actor)
    application = _one(connection, SELECT_APPLICATION, (record.application_id,))
    if application is None:
        raise InventoryError("forbidden", "Application was not found")
    if record.snapshot_id is not None:
        snapshot = _one(connection, SELECT_SNAPSHOT_OWNER, (record.snapshot_id,))
        if snapshot is None or snapshot["application_id"] != record.application_id:
            raise InventoryError("forbidden", "Deployment snapshot belongs to another application")
        if record.commit_sha and record.commit_sha != snapshot["commit_ref"]:
            raise InventoryError(
                "invalid_response", "Deployment commit does not match the snapshot"
            )
    deployment_id = uuid4()
    _one(
        connection,
        INSERT_DEPLOYMENT,
        (
            deployment_id,
            record.application_id,
            record.snapshot_id,
            record.environment,
            record.artifact_ref,
            record.source_reference,
            record.deployed_at,
            record.retired_at,
            record.commit_sha,
        ),
    )
    connection.execute(INSERT_AUDIT, (deployment_id, actor, "deployment.imported"))
    return deployment_id


def import_deployments(
    connection: SQLConnection,
    payload: dict,
    *,
    application: AuthorizedApplication,
    snapshots: list | tuple = (),
    actor: str,
) -> list[UUID]:
    records = parse_deployment_document(payload, application=application, snapshots=snapshots)
    return [insert_deployment(connection, record, actor=actor) for record in records]


def retire_deployment(
    connection: SQLConnection,
    deployment_id: UUID,
    *,
    application_id: UUID,
    retired_at,
    actor: str,
) -> None:
    """Set a retirement time. The deployment row remains."""
    actor = _actor(actor)
    row = _one(connection, SELECT_DEPLOYMENT, (deployment_id,))
    if row is None or row["application_id"] != application_id:
        raise InventoryError("forbidden", "Deployment belongs to another application")
    if row["retired_at"] is not None:
        raise InventoryError("invalid_response", "Deployment is already retired")
    if retired_at < row["deployed_at"]:
        raise InventoryError("invalid_response", "retired_at is earlier than deployed_at")
    connection.execute(RETIRE_DEPLOYMENT, (retired_at, deployment_id, application_id))
    connection.execute(INSERT_AUDIT, (deployment_id, actor, "deployment.retired"))


def list_snapshots(connection: SQLConnection, application_id: UUID) -> list[dict]:
    result = connection.execute(LIST_SNAPSHOTS, (application_id,))
    return list(result.fetchall())


def _one(connection: SQLConnection, sql: str, params: tuple):
    result = connection.execute(sql, params)
    if result is None:
        return None
    return result.fetchone()


def _json(value) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _actor(actor: str) -> str:
    if not isinstance(actor, str) or not actor or actor.strip() != actor or len(actor) > 200:
        raise InventoryError("configuration", "Audit actor is missing")
    if any(ord(char) < 32 for char in actor):
        raise InventoryError("configuration", "Audit actor is invalid")
    return actor
