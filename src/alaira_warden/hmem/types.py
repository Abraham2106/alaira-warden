"""Canonical H-MEM shapes. Field names match AGENTS.md / the TypeScript reference."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

MemoryType = Literal["personal", "factual", "preference", "general"]
MemoryLayer = Literal["short_term", "working", "long_term"]
ProvenanceOrigin = Literal[
    "chat_message",
    "user_correction",
    "file_save",
    "file_open",
    "file_edit",
    "model_response",
    "plan_completion",
    "document",
    "manual",
    "dream",
    "sleep_synthesis",
]
LedgerAction = Literal[
    "create",
    "read",
    "update",
    "delete",
    "feedback",
    "promote",
    "demote",
    "merge",
    "conflict_detected",
    "conflict_resolved",
    "sleep_consolidate",
    "sleep_archive",
    "sleep_synthesize",
    "dream_proposed",
    "dream_approved",
    "dream_rejected",
    "restore",
]
MiningEventType = Literal[
    "chat_message",
    "user_correction",
    "file_save",
    "file_open",
    "file_edit",
    "model_response",
    "plan_completion",
]
DreamProposalType = Literal["insight", "domain", "invariant"]
FeedbackKind = Literal["helpful", "not_helpful", "wrong"]
ConflictResolution = Literal["keep_a", "keep_b", "keep_both", "merge", "delete_both"]

FEEDBACK_DELTAS: dict[FeedbackKind, float] = {
    "helpful": 0.05,
    "not_helpful": -0.03,
    "wrong": -0.2,
}

DEFAULTS = {
    "retrievalTopN": 5,
    "retrievalThreshold": 0.35,
    "consolidationDays": 7,
    "archiveMinDays": 30,
    "archiveMaxAccess": 2,
    "synthesisCosine": 0.82,
    "dreamClusterMinSize": 2,
    "dreamRelatedness": 0.35,
    "maxDreamProposalsPerType": 8,
    "conflictAutoResolveGate": 0.7,
    "entityCap": 10,
    "relatedCap": 5,
    "recencyDays": 14,
}

DAY_MS = 24 * 60 * 60 * 1000


def clamp01(x: float) -> float:
    return min(1.0, max(0.0, x))


@dataclass
class Provenance:
    origin: str
    learnedAt: int
    label: str
    refs: list[str] | None = None


@dataclass
class MemoryRecord:
    id: str
    content: str
    type: str
    layer: str
    timestamp: int
    lastAccessed: int
    accessCount: int
    tags: list[str]
    embedding: list[float]
    confidence: float
    source: str
    provenance: Provenance
    domain: str
    namespace: str
    entities: list[str]
    relatedTo: list[str]
    score: float | None = None
    chatId: str | None = None
    missionId: str | None = None
    goalRunId: str | None = None
    supersedes: str | None = None
    supersededBy: str | None = None
    derivedFrom: list[str] | None = None


@dataclass
class LedgerEntry:
    memoryId: str
    action: str
    actor: str
    timestamp: int
    previousState: dict[str, Any] | None = None
    newState: dict[str, Any] | None = None
    details: dict[str, Any] | None = None


@dataclass
class DreamProposal:
    id: str
    type: str
    content: str
    derivedFrom: list[str]
    status: str
    suggestedDomain: str | None = None


@dataclass
class SleepPreview:
    toConsolidate: list[str]
    toArchive: list[str]
    toSynthesize: list[list[str]]


@dataclass
class SleepReport:
    backupId: str
    consolidated: int
    archived: int
    synthesized: int
    actionLog: list[str]


@dataclass
class ConflictRecord:
    id: str
    memoryA: str
    memoryB: str
    reason: str
    confidence: float
    resolved: bool
    resolution: str | None = None


@dataclass
class RetrievedMemory:
    memory: MemoryRecord
    relevance: float


@dataclass
class QueryResult:
    memories: list[RetrievedMemory]
    context: str
    trace: dict[str, Any]


MinerFn = Callable[[str], str]
ClockFn = Callable[[], int]


@dataclass
class AddInput:
    content: str
    source: str
    type: str = "general"
    layer: str = "working"
    tags: list[str] = field(default_factory=list)
    confidence: float | None = None
    provenance: Provenance | None = None
    chatId: str | None = None
    missionId: str | None = None
    goalRunId: str | None = None
    supersedes: str | None = None
    derivedFrom: list[str] | None = None
