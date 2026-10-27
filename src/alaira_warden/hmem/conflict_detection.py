"""Conflict detection. The loser is marked supersededBy, never deleted."""

from __future__ import annotations

import re

from alaira_warden.hmem.embeddings import cosine
from alaira_warden.hmem.memory_store import MemoryStoreService, snapshot
from alaira_warden.hmem.trust_ledger import TrustLedgerService
from alaira_warden.hmem.types import DEFAULTS, ClockFn, ConflictRecord, MemoryRecord, clamp01

OPPOSING_PAIRS = [
    (re.compile(r"\balways\b", re.I), re.compile(r"\bnever\b", re.I)),
    (re.compile(r"\benable[ds]?\b", re.I), re.compile(r"\bdisable[ds]?\b", re.I)),
    (re.compile(r"\bprefer[s]?\b", re.I), re.compile(r"\bavoid[s]?|dislike[s]?\b", re.I)),
    (re.compile(r"\bon\b", re.I), re.compile(r"\boff\b", re.I)),
    (re.compile(r"\byes\b", re.I), re.compile(r"\bno\b", re.I)),
]


class ConflictDetectionService:
    def __init__(
        self,
        store: MemoryStoreService,
        ledger: TrustLedgerService,
        clock: ClockFn,
        actor: str,
    ):
        self._store = store
        self._ledger = ledger
        self._clock = clock
        self._actor = actor
        self._conflicts: list[ConflictRecord] = []
        self.seq = 0

    def scan(self) -> list[ConflictRecord]:
        found: list[ConflictRecord] = []
        all_records = self._store.all()
        for i, left in enumerate(all_records):
            for right in all_records[i + 1 :]:
                conflict = self._check(left, right)
                if conflict:
                    found.append(conflict)
                    self._conflicts.append(conflict)
                    self._ledger.log(
                        conflict.memoryA,
                        "conflict_detected",
                        self._actor,
                        {
                            "details": {
                                "with": conflict.memoryB,
                                "reason": conflict.reason,
                                "confidence": conflict.confidence,
                            }
                        },
                    )
        return found

    def _check(self, left: MemoryRecord, right: MemoryRecord) -> ConflictRecord | None:
        if (
            left.supersedes == right.id
            or right.supersedes == left.id
            or left.supersededBy == right.id
            or right.supersededBy == left.id
        ):
            return None
        similar = cosine(left.embedding, right.embedding)
        reason = ""
        confidence = 0.0
        for first, second in OPPOSING_PAIRS:
            if (first.search(left.content) and second.search(right.content)) or (
                second.search(left.content) and first.search(right.content)
            ):
                if similar > 0.5:
                    reason = "opposing phrase pair on similar content"
                    confidence = 0.5 + 0.3 * similar
        if not reason and similar > 0.8:
            nums_a = re.findall(r"\d+(?:\.\d+)?", left.content)
            nums_b = re.findall(r"\d+(?:\.\d+)?", right.content)
            if nums_a and nums_b and ",".join(nums_a) != ",".join(nums_b):
                reason = "high-similarity conflicting numeric values"
                confidence = 0.55 + 0.25 * similar
        if not reason:
            return None
        shared = [entity for entity in left.entities if entity in right.entities]
        if shared:
            confidence += 0.1
        if left.domain == right.domain:
            confidence += 0.05
        if right.id in left.relatedTo:
            confidence -= 0.1
        self.seq += 1
        return ConflictRecord(
            id=f"conflict-{self.seq}",
            memoryA=left.id,
            memoryB=right.id,
            reason=reason,
            confidence=clamp01(confidence),
            resolved=False,
        )

    def auto_resolve(self, conflict: ConflictRecord) -> str:
        left = self._store.get(conflict.memoryA)
        right = self._store.get(conflict.memoryB)
        if left is None or right is None:
            raise ValueError("H-MEM: conflict references a missing memory")

        def score_of(memory: MemoryRecord) -> float:
            return (
                0.3 * (memory.lastAccessed / max(1, self._clock()))
                + 0.2 * min(1.0, memory.accessCount / 10)
                + 0.25 * memory.confidence
                + 0.1 * min(1.0, len(memory.content) / 200)
                + 0.15 * (1 if memory.provenance.origin == "user_correction" else 0.5)
            )

        score_a = score_of(left)
        score_b = score_of(right)
        margin = abs(score_a - score_b) / max(score_a, score_b)
        decision_confidence = clamp01(conflict.confidence * 0.6 + margin * 0.8)
        if decision_confidence < DEFAULTS["conflictAutoResolveGate"]:
            return "queued"
        winner = left if score_a >= score_b else right
        loser = right if score_a >= score_b else left
        previous = snapshot(loser)
        loser.supersededBy = winner.id
        conflict.resolved = True
        conflict.resolution = "keep_a" if winner.id == conflict.memoryA else "keep_b"
        self._ledger.log(
            loser.id,
            "conflict_resolved",
            self._actor,
            {
                "previousState": previous,
                "newState": snapshot(loser),
                "details": {
                    "conflictId": conflict.id,
                    "winner": winner.id,
                    "decisionConfidence": float(f"{decision_confidence:.3f}"),
                },
            },
        )
        self._store.persist()
        return "resolved"

    def queue(self) -> list[ConflictRecord]:
        return [item for item in self._conflicts if not item.resolved]

    def all(self) -> list[ConflictRecord]:
        return list(self._conflicts)

    def restore(self, conflicts: list[ConflictRecord]) -> None:
        self._conflicts = list(conflicts)
        self.seq = max((int(item.id.split("-")[1]) for item in conflicts), default=0)
