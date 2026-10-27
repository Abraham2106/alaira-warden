"""H-MEM facade. Deterministic in-memory store with optional JSON persistence."""

from __future__ import annotations

import time
from typing import Any

from alaira_warden.hmem.conflict_detection import ConflictDetectionService
from alaira_warden.hmem.dreaming import DreamingService
from alaira_warden.hmem.memory_mining import MemoryMiningService
from alaira_warden.hmem.memory_retrieval import MemoryRetrievalService
from alaira_warden.hmem.memory_store import MemoryStoreService
from alaira_warden.hmem.sleep_cycle import SleepCycleService
from alaira_warden.hmem.trust_ledger import TrustLedgerService
from alaira_warden.hmem.types import MemoryRecord, QueryResult


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


class HMEM:
    def __init__(self, opts: dict | None = None, **kwargs):
        options = {**(opts or {}), **kwargs}
        clock = options.get("clock") or _now_ms
        persist_dir = options.get("persistDir") or options.get("persist_dir")
        actor = options.get("actor") or "system"
        miner_fn = options.get("minerFn") or options.get("miner_fn")
        self.clock = clock
        self.ledger = TrustLedgerService(self.clock, persist_dir)
        self.store = MemoryStoreService(self.clock, self.ledger, actor, persist_dir)
        self.mining = MemoryMiningService(self.store, self.clock, miner_fn)
        self.retrieval = MemoryRetrievalService(self.store, self.ledger, self.clock, actor)
        self.conflicts = ConflictDetectionService(self.store, self.ledger, self.clock, actor)
        self.sleep = SleepCycleService(self.store, self.ledger, self.clock, actor)
        self.dreaming = DreamingService(self.store, self.ledger, self.clock, actor)

    def add(self, payload: dict | Any) -> MemoryRecord:
        return self.store.add(payload)

    def mine(self, event: str, text: str, opts: dict | None = None) -> list[MemoryRecord]:
        return self.mining.mine_interaction(event, text, opts)

    def query(self, query: str, opts: dict | None = None) -> QueryResult:
        return self.retrieval.query(query, opts)

    def feedback(self, memory_id: str, kind: str) -> None:
        self.retrieval.feedback(memory_id, kind)
