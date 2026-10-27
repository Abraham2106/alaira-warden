"""Historical deployment import. Records are append-only observations.

schema_version 1 document:

{
  "schema_version": 1,
  "deployments": [
    {
      "application_id": "<uuid of the application being imported>",
      "environment": "production",
      "artifact_ref": "registry.example/app@sha256:...",
      "commit_sha": "<40 lowercase hex>",
      "snapshot_id": null,
      "deployed_at": "2024-01-01T00:00:00Z",
      "retired_at": null,
      "source_reference": "change-ticket:CHG-100"
    }
  ]
}

A deployment proves deployment only. The document has no field for code execution.
"""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from alaira_warden.inventory.errors import InventoryError
from alaira_warden.inventory.models import (
    AuthorizedApplication,
    DeploymentRecord,
    validate_commit_sha,
)

SCHEMA_VERSION = 1


class KnownSnapshot(BaseModel):
    """Identity of a snapshot the integrator already stored."""

    model_config = ConfigDict(extra="forbid")

    snapshot_id: UUID
    application_id: UUID
    commit_sha: str

    @field_validator("commit_sha")
    @classmethod
    def commit(cls, value: str) -> str:
        return validate_commit_sha(value)


class DeploymentImportDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    deployments: list[DeploymentRecord] = Field(min_length=1)


def parse_deployment_document(
    payload: dict,
    *,
    application: AuthorizedApplication,
    snapshots: list[KnownSnapshot] | tuple[KnownSnapshot, ...] = (),
) -> list[DeploymentRecord]:
    if not isinstance(payload, dict):
        raise InventoryError("invalid_response", "Deployment import must be a JSON object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise InventoryError("unsupported", "Deployment import schema_version must be 1")
    try:
        document = DeploymentImportDocument.model_validate(payload)
    except ValidationError as exc:
        fields = ", ".join(str(error["loc"][-1]) for error in exc.errors())
        raise InventoryError(
            "invalid_response", f"Invalid deployment import fields: {fields}"
        ) from None
    snapshot_ids = {item.snapshot_id: item for item in snapshots}
    records: list[DeploymentRecord] = []
    for record in document.deployments:
        if record.application_id != application.application_id:
            raise InventoryError("forbidden", "Deployment refers to another application")
        if application.environments and record.environment not in application.environments:
            raise InventoryError("invalid_response", "Deployment environment is not registered")
        if record.snapshot_id is not None:
            snapshot = snapshot_ids.get(record.snapshot_id)
            if snapshot is None or snapshot.application_id != application.application_id:
                raise InventoryError(
                    "forbidden", "Deployment snapshot belongs to another application"
                )
            if record.commit_sha and record.commit_sha != snapshot.commit_sha:
                raise InventoryError(
                    "invalid_response", "Deployment commit does not match the snapshot"
                )
        records.append(record)
    return records


def append_deployments(
    existing: list[DeploymentRecord], imported: list[DeploymentRecord]
) -> list[DeploymentRecord]:
    """Keep every previous deployment and add the imported observations."""
    return [*existing, *imported]
