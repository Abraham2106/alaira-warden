"""Hybrid retrieval. Confidence multiplies after the weighted sum."""

from __future__ import annotations

import math

from alaira_warden.hmem.embeddings import cosine, embed, jaccard, tokenize
from alaira_warden.hmem.memory_store import MemoryStoreService, snapshot
from alaira_warden.hmem.trust_ledger import TrustLedgerService
from alaira_warden.hmem.types import (
    DAY_MS,
    DEFAULTS,
    FEEDBACK_DELTAS,
    ClockFn,
    MemoryRecord,
    QueryResult,
    RetrievedMemory,
    clamp01,
)

LAYER_WEIGHT = {"long_term": 1.0, "working": 0.8, "short_term": 0.6}


class MemoryRetrievalService:
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

    def score_one(self, memory: MemoryRecord, query: str) -> float:
        return self._score(
            memory,
            embed(query),
            tokenize(query)[:8],
            self._store.extract_entities(query),
            self._store.classify_domain(query, [], "general"),
        )

    def _score(
        self,
        memory: MemoryRecord,
        query_embedding: list[float],
        query_tokens: list[str],
        query_entities: list[str],
        query_domain: str,
    ) -> float:
        semantic = clamp01(cosine(query_embedding, memory.embedding))
        keyword = jaccard(query_tokens, tokenize(memory.content))
        tag = jaccard(query_tokens, [item.lower() for item in memory.tags])
        domain = 1 if memory.domain == query_domain else 0
        entity = jaccard(query_entities, memory.entities)
        layer = LAYER_WEIGHT[memory.layer]
        age_days = (self._clock() - memory.lastAccessed) / DAY_MS
        recency = math.exp(-age_days / DEFAULTS["recencyDays"])
        superseded = 1 if memory.supersededBy else 0
        raw = (
            0.35 * semantic
            + 0.2 * keyword
            + 0.1 * tag
            + 0.1 * domain
            + 0.15 * entity
            + 0.05 * layer
            + 0.05 * recency
            - 0.2 * superseded
        )
        return clamp01(raw) * memory.confidence

    def query(self, query: str, opts: dict | None = None) -> QueryResult:
        options = opts or {}
        query_embedding = embed(query)
        query_tokens = tokenize(query)[:8]
        query_entities = self._store.extract_entities(query)
        query_domain = self._store.classify_domain(query, [], "general")
        threshold = options.get("threshold", DEFAULTS["retrievalThreshold"])
        top_n = options.get("topN", DEFAULTS["retrievalTopN"])
        chat_id = options.get("chatId")

        scored: list[RetrievedMemory] = []
        for memory in self._store.all():
            if chat_id and memory.chatId and memory.chatId != chat_id:
                continue
            relevance = self._score(
                memory, query_embedding, query_tokens, query_entities, query_domain
            )
            if relevance >= threshold:
                scored.append(RetrievedMemory(memory=memory, relevance=relevance))
        scored.sort(key=lambda item: (-item.relevance, item.memory.id))
        top = scored[:top_n]
        for item in top:
            self._store.touch(item.memory.id)
            self._ledger.log(item.memory.id, "read", self._actor, {"details": {"query": query}})

        if len(top) <= 1:
            strategy = "minimal"
        elif any(item.memory.type in {"personal", "preference"} for item in top):
            strategy = "personal"
        else:
            strategy = "comprehensive"
        return QueryResult(
            memories=top,
            context=self.format_reinjection(top),
            trace={
                "retrievalReason": f'hybrid ranking for "{query}" (domain: {query_domain})',
                "strategy": strategy,
                "scores": {item.memory.id: float(f"{item.relevance:.4f}") for item in top},
            },
        )

    def format_reinjection(self, items: list[RetrievedMemory]) -> str:
        if not items:
            return ""
        by_domain: dict[str, list[RetrievedMemory]] = {}
        for item in items:
            by_domain.setdefault(item.memory.domain, []).append(item)
        lines = ["[MEMORY CONTEXT]"]
        for domain in sorted(by_domain):
            lines.append(f"## {domain}")
            for item in by_domain[domain]:
                memory = item.memory
                if memory.layer == "long_term":
                    marker = "LT"
                elif memory.layer == "working":
                    marker = "WK"
                else:
                    marker = "ST"
                ents = f" (entities: {', '.join(memory.entities)})" if memory.entities else ""
                lines.append(f"- [{marker}] {memory.content}{ents} <{memory.id}>")
        lines.append("[/MEMORY CONTEXT]")
        return "\n".join(lines)

    def feedback(self, memory_id: str, kind: str) -> None:
        memory = self._store.get(memory_id)
        if memory is None:
            raise ValueError(f"H-MEM: unknown memory id {memory_id}")
        previous = snapshot(memory)
        if kind == "helpful":
            memory.accessCount += 1
        memory.confidence = clamp01(memory.confidence + FEEDBACK_DELTAS[kind])
        if kind == "wrong" and "review" not in memory.tags:
            memory.tags.append("review")
        self._ledger.log(
            memory_id,
            "feedback",
            self._actor,
            {
                "previousState": previous,
                "newState": snapshot(memory),
                "details": {"kind": kind, "delta": FEEDBACK_DELTAS[kind]},
            },
        )
        self._store.persist()
