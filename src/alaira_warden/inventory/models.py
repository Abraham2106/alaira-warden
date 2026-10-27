"""Local v1 inventory and deployment records.

Serialization keeps the roadmap names. `metadata` and warning fields are
additive context for the integrator; they do not declare vulnerabilities.
"""

import re
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SHA_RE = re.compile(r"[0-9a-f]{40}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}")
ENVIRONMENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")

Completeness = Literal["complete", "partial", "failed"]


def require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("timestamp requires a timezone")
    return value.astimezone(UTC)


def validate_repository_name(value: str) -> str:
    if not REPOSITORY_RE.fullmatch(value):
        raise ValueError("Use GitHub owner/repository, not a URL or local path.")
    if value.split("/")[1] in {".", ".."}:
        raise ValueError("Invalid repository name.")
    return value


def validate_commit_sha(value: str) -> str:
    if not SHA_RE.fullmatch(value):
        raise ValueError("commit_sha must be a 40-character lowercase hex digest")
    return value


class InventoryWarning(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=80)
    message: str = Field(min_length=1, max_length=500)
    path: str | None = None
    component: str | None = None
    blocks_completeness: bool = False


class Component(BaseModel):
    """One resolved or explicitly unresolved npm component.

    `dependency_paths` is a list of chains. Each chain is ordered from a
    direct dependency to this component. A step is `name@version` or
    `name@unresolved`. The same package name can appear in several components
    when the resolved versions differ; `metadata.lock_path` keeps the lockfile
    node that produced the row.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=214)
    ecosystem: Literal["npm"] = "npm"
    resolved_version: str | None = None
    direct: bool
    dependency_paths: list[list[str]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("resolved_version")
    @classmethod
    def concrete_version(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(mark in value for mark in ("^", "~", "*", " ", "<", ">", "|", "||")):
            raise ValueError("resolved_version cannot be a range")
        return value


class InventorySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: UUID
    repository: str
    commit_sha: str
    observed_at: datetime
    tool_name: str = Field(min_length=1, max_length=80)
    tool_version: str = Field(min_length=1, max_length=80)
    completeness: Completeness
    components: list[Component]
    warnings: list[InventoryWarning]
    artifact_path: str | None = None
    artifact_hash: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("repository")
    @classmethod
    def repository_name(cls, value: str) -> str:
        return validate_repository_name(value)

    @field_validator("commit_sha")
    @classmethod
    def commit(cls, value: str) -> str:
        return validate_commit_sha(value)

    @field_validator("observed_at")
    @classmethod
    def observed(cls, value: datetime) -> datetime:
        return require_utc(value)

    @field_validator("artifact_hash")
    @classmethod
    def artifact(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("artifact_hash must be a sha256 hex digest")
        return value


class AuthorizedApplication(BaseModel):
    """RF-01 facts supplied by the integrator. This package does not persist them."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    application_id: UUID
    repository: str
    environments: tuple[str, ...] = ()
    owner: str | None = Field(default=None, max_length=200)
    criticality: Literal["low", "medium", "high", "critical"] | None = None

    @field_validator("repository")
    @classmethod
    def repository_name(cls, value: str) -> str:
        return validate_repository_name(value)

    @field_validator("environments")
    @classmethod
    def environment_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            if not ENVIRONMENT_RE.fullmatch(item):
                raise ValueError("Invalid environment name")
        if len(set(value)) != len(value):
            raise ValueError("Duplicate environment")
        return value


class DeploymentRecord(BaseModel):
    """A deployment observation.

    `execution_evidence` stays `not_asserted`. A deployment record does not
    show that the artifact's code ran.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    application_id: UUID
    environment: str
    artifact_ref: str = Field(min_length=1, max_length=500)
    commit_sha: str | None = None
    snapshot_id: UUID | None = None
    deployed_at: datetime
    retired_at: datetime | None = None
    source_reference: str = Field(min_length=1, max_length=500)
    execution_evidence: Literal["not_asserted"] = "not_asserted"

    @field_validator("environment")
    @classmethod
    def environment_name(cls, value: str) -> str:
        if not ENVIRONMENT_RE.fullmatch(value):
            raise ValueError("Invalid environment name")
        return value

    @field_validator("commit_sha")
    @classmethod
    def commit(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_commit_sha(value)

    @field_validator("deployed_at", "retired_at")
    @classmethod
    def timestamps(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return require_utc(value)

    @model_validator(mode="after")
    def identity(self) -> "DeploymentRecord":
        if self.commit_sha is None and self.snapshot_id is None:
            raise ValueError("deployment requires a commit_sha or a snapshot_id")
        if self.retired_at is not None and self.retired_at < self.deployed_at:
            raise ValueError("retired_at is earlier than deployed_at")
        return self


class InventoryAssessment(BaseModel):
    """Freshness view. It does not rewrite the snapshot that was stored."""

    model_config = ConfigDict(extra="forbid")

    completeness: Completeness
    expired: bool
    limits_conclusion: bool
    warnings: list[InventoryWarning]
    max_age_seconds: int = Field(ge=1)
