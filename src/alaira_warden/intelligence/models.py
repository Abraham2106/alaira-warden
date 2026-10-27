"""Local v1 records for intelligence sources.

Serialized names match ``docs/implementation-roadmap.md``. Fields beyond that
contract (``origin``, ``warnings``, ``attribution``, ``advisory_kind``,
``source_status``, ``changes``, ``received_at``) are additive. ``source="manual"``
is the intake extension requested for RF-09; the four catalog sources stay
``github``, ``osv``, ``nvd`` and ``cisa-kev``.

``known_exploited is None`` means the source did not establish exploitation.
It is not a negative finding. Severity entries keep the producing system and are
not collapsed into one score. Affected ranges keep the source's own expression.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SourceName = Literal["github", "osv", "nvd", "cisa-kev", "manual"]
EvidenceClass = Literal["confirmed", "preliminary", "contradictory", "insufficient"]
_HASH = re.compile(r"^[0-9a-f]{64}$")


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must include a timezone")
    return value.astimezone(UTC)


class AffectedEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem: str | None = None
    package_name: str | None = None
    ranges: list[Any] = Field(default_factory=list)
    versions: list[str] | None = None


class Severity(BaseModel):
    """Original severity. ``score`` is set only when the source provided a number."""

    model_config = ConfigDict(extra="forbid")

    system: str | None = None
    value: str | None = None
    score: float | None = None
    source: str | None = None
    raw: Any = None


class KnownExploited(BaseModel):
    model_config = ConfigDict(extra="forbid")

    known: bool | None = None
    source: str
    catalog_version: str | None = None
    date_added: datetime | None = None
    ransomware_use: str | None = None
    detail: str | None = None

    @field_validator("date_added")
    @classmethod
    def _date(cls, value: datetime | None) -> datetime | None:
        return _as_utc(value)


class Attribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    documentation_url: str
    notes: str


class SourceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: SourceName
    source_id: str = Field(min_length=1)
    aliases: list[str] = Field(default_factory=list)
    title: str | None = None
    summary: str | None = None
    source_url: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    retrieved_at: datetime
    content_hash: str
    references: list[str] = Field(default_factory=list)
    affected: list[AffectedEntry] = Field(default_factory=list)
    severity: list[Severity] = Field(default_factory=list)
    known_exploited: KnownExploited | None = None
    license: str | None = None
    attribution: Attribution
    origin: dict[str, Any]
    warnings: list[str] = Field(default_factory=list)
    advisory_kind: str | None = None
    source_status: str | None = None
    changes: list[dict[str, Any]] = Field(default_factory=list)
    received_at: datetime | None = None

    @field_validator("published_at", "modified_at", "retrieved_at", "received_at")
    @classmethod
    def _timestamps(cls, value: datetime | None) -> datetime | None:
        return _as_utc(value)

    @field_validator("content_hash")
    @classmethod
    def _hash(cls, value: str) -> str:
        if not _HASH.fullmatch(value):
            raise ValueError("content_hash must be a lowercase sha256 hex digest")
        return value


class SourceBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: SourceName
    retrieved_at: datetime
    records: list[SourceRecord]
    complete: bool
    next_cursor: str | None = None
    warnings: list[str] = Field(default_factory=list)

    @field_validator("retrieved_at")
    @classmethod
    def _retrieved(cls, value: datetime) -> datetime:
        converted = _as_utc(value)
        if converted is None:
            raise ValueError("retrieved_at is required")
        return converted


class MemberRevision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    source_id: str
    content_hash: str
    modified_at: datetime | None = None
    retrieved_at: datetime

    @field_validator("modified_at", "retrieved_at")
    @classmethod
    def _timestamps(cls, value: datetime | None) -> datetime | None:
        return _as_utc(value)


class IdentifierLink(BaseModel):
    """Why records share a group. The link is an identifier, never a similar title."""

    model_config = ConfigDict(extra="forbid")

    identifier: str
    members: list[str]
    ambiguous: bool = False


class AdvisoryGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_id: str
    identifiers: list[str]
    members: list[SourceRecord]
    links: list[IdentifierLink]
    ambiguous_identifiers: list[str] = Field(default_factory=list)
    revisions: dict[str, list[MemberRevision]] = Field(default_factory=dict)
    independent_report_count: int
    evidence_class: EvidenceClass
    justification: str
    warnings: list[str] = Field(default_factory=list)


class GroupingResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    groups: list[AdvisoryGroup]
    warnings: list[str] = Field(default_factory=list)


class KevLookup(BaseModel):
    """A miss keeps ``known_exploited`` null. That is not proof of no exploitation."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str
    found: bool
    known_exploited: KnownExploited | None = None
    record: SourceRecord | None = None


class SourceAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    operation: str
    ok: bool
    complete: bool | None = None
    record_count: int = 0
    error_category: str | None = None
    warnings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ConsultationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attempts: list[SourceAttempt]
    unverified: list[str] = Field(default_factory=list)


class SyncPlan(BaseModel):
    """A suggested poll. This module does not start a scheduler."""

    model_config = ConfigDict(extra="forbid")

    source: str
    operation: str
    interval_seconds: int | None
    notes: str
