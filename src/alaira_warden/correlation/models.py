from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

Exposure = Literal["not_affected", "potential", "confirmed", "undetermined"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class VersionRange(Contract):
    type: str = Field(max_length=32)
    expression: str | None = Field(default=None, max_length=2048)
    events: tuple[dict[str, str], ...] = Field(default=(), max_length=256)


class PackageRule(Contract):
    ecosystem: str = Field(max_length=64)
    package_name: str = Field(min_length=1, max_length=214)
    versions: tuple[str, ...] = Field(default=(), max_length=10000)
    ranges: tuple[VersionRange, ...] = Field(default=(), max_length=128)


class Advisory(Contract):
    source_id: str = Field(min_length=1, max_length=256)
    source: str = Field(max_length=64)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    affected: tuple[PackageRule, ...] = Field(default=(), max_length=256)
    affected_complete: bool = False
    evidence_status: Literal["confirmed", "preliminary", "contradictory", "insufficient"]
    severity_score: float | None = Field(default=None, ge=0, le=10)
    known_exploited: bool | None = None
    withdrawn: bool = False


class Component(Contract):
    id: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=214)
    ecosystem: str = "npm"
    resolved_version: str | None = Field(default=None, max_length=256)
    dependency_paths: tuple[tuple[str, ...], ...] = ()


class Snapshot(Contract):
    id: UUID
    application_id: UUID
    commit_sha: str = Field(pattern=r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
    observed_at: AwareDatetime
    completeness: Literal["complete", "partial", "failed"]
    components: tuple[Component, ...] = Field(default=(), max_length=10000)


class Condition(Contract):
    name: str = Field(min_length=1, max_length=256)
    satisfied: bool | None
    evidence_reference: str | None = None


class Context(Contract):
    application_id: UUID
    snapshot_id: UUID
    deployed: bool | None = None
    deployment_reference: str | None = None
    environment: str | None = None
    historical: bool = False
    deployed_at: AwareDatetime | None = None
    conditions_complete: bool = False
    conditions: tuple[Condition, ...] = ()
    asset_criticality: Literal["low", "medium", "high", "critical"] = "medium"


class PriorityPolicy(Contract):
    version: Literal["warden-priority-v1"] = "warden-priority-v1"
    max_inventory_age_seconds: int = Field(default=86400, ge=1, le=2592000)


class Match(Contract):
    affected: bool | None
    reasons: tuple[str, ...]


class Finding(Contract):
    component_id: str
    package_name: str
    resolved_version: str | None
    dependency_paths: tuple[tuple[str, ...], ...]
    version_affected: bool | None
    exposure: Exposure
    compromise: Literal["unknown"] = "unknown"
    priority: Literal["none", "unassigned", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    reasons: tuple[str, ...]


class Assessment(Contract):
    application_id: UUID
    snapshot_id: UUID
    commit_sha: str
    advisory_id: str
    advisory_revision: str
    policy_version: str
    evaluated_at: datetime
    historical: bool
    exposure: Exposure
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...]
