"""Tiered memory store with enrichment. A record with no source is rejected."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path

from alaira_warden.hmem.embeddings import cosine, embed, tokenize
from alaira_warden.hmem.trust_ledger import TrustLedgerService
from alaira_warden.hmem.types import (
    DEFAULTS,
    AddInput,
    ClockFn,
    MemoryRecord,
    Provenance,
    clamp01,
)

TECH_TERMS = [
    "react",
    "python",
    "typescript",
    "javascript",
    "rust",
    "sqlite",
    "postgres",
    "indexeddb",
    "node",
    "docker",
    "graphql",
    "redis",
    "webrtc",
    "tauri",
    "electron",
    "llm",
    "embedding",
]
DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "tech": [
        "code",
        "bug",
        "api",
        "database",
        "deploy",
        "framework",
        "library",
        "server",
        *TECH_TERMS,
    ],
    "work": ["meeting", "deadline", "client", "project", "sprint", "review", "report"],
    "personal": ["family", "hobby", "prefer", "like", "dislike", "morning", "evening"],
}
_CORRECTION = re.compile(
    r"\b(actually|instead|no longer|not anymore|changed to|correction)\b", re.I
)
_ENTITY = re.compile(r"\b([A-Z][a-zA-Z]{2,})\b")


class MemoryStoreService:
    def __init__(
        self,
        clock: ClockFn,
        ledger: TrustLedgerService,
        actor: str,
        persist_dir: str | None = None,
    ):
        self._clock = clock
        self._ledger = ledger
        self._actor = actor
        self._records: dict[str, MemoryRecord] = {}
        self.seq = 0
        self._state_file: Path | None = None
        if persist_dir:
            directory = Path(persist_dir)
            directory.mkdir(parents=True, exist_ok=True)
            self._state_file = directory / "state.json"
            if self._state_file.exists():
                saved = json.loads(self._state_file.read_text(encoding="utf-8"))
                self.seq = saved["seq"]
                for item in saved["records"]:
                    record = record_from_json(item)
                    self._records[record.id] = record

    def persist(self) -> None:
        if not self._state_file:
            return
        records = [
            record_to_json(item) for item in sorted(self._records.values(), key=lambda r: r.id)
        ]
        payload = json.dumps({"seq": self.seq, "records": records}, indent=2) + "\n"
        self._state_file.write_text(payload, encoding="utf-8")

    def add(self, payload: AddInput | dict) -> MemoryRecord:
        incoming = payload if isinstance(payload, AddInput) else add_input_from_mapping(payload)
        if not incoming.source or not incoming.source.strip():
            raise ValueError(
                "H-MEM: a memory record with no source must be rejected by construction "
                "(AGENTS.md section 2)"
            )
        now = self._clock()
        self.seq += 1
        identifier = f"mem-{self.seq}"
        tags = list(incoming.tags)
        memory_type = incoming.type or "general"
        domain = self.classify_domain(incoming.content, tags, memory_type)
        record = MemoryRecord(
            id=identifier,
            content=incoming.content,
            type=memory_type,
            layer=incoming.layer or "working",
            timestamp=now,
            lastAccessed=now,
            accessCount=0,
            tags=tags,
            embedding=embed(incoming.content),
            confidence=clamp01(0.7 if incoming.confidence is None else incoming.confidence),
            source=incoming.source,
            provenance=incoming.provenance
            or Provenance(origin="manual", learnedAt=now, label=incoming.source),
            chatId=incoming.chatId,
            missionId=incoming.missionId,
            goalRunId=incoming.goalRunId,
            domain=domain,
            namespace=self._namespace(domain, memory_type),
            entities=self.extract_entities(incoming.content),
            relatedTo=[],
            supersedes=incoming.supersedes,
            derivedFrom=incoming.derivedFrom,
        )
        self._discover_relationships(record)
        self._records[identifier] = record
        self._ledger.log(identifier, "create", self._actor, {"newState": snapshot(record)})
        self.persist()
        return record

    def get(self, identifier: str) -> MemoryRecord | None:
        return self._records.get(identifier)

    def all(self) -> list[MemoryRecord]:
        return list(self._records.values())

    def update(self, identifier: str, patch: dict) -> MemoryRecord:
        record = self._must_get(identifier)
        previous = snapshot(record)
        for key, value in patch.items():
            setattr(record, key, value)
        self._ledger.log(
            identifier,
            "update",
            self._actor,
            {"previousState": previous, "newState": snapshot(record)},
        )
        self.persist()
        return record

    def delete(self, identifier: str, reason: str) -> None:
        record = self._must_get(identifier)
        del self._records[identifier]
        self._ledger.log(
            identifier,
            "delete",
            self._actor,
            {"previousState": snapshot(record), "details": {"reason": reason}},
        )
        self.persist()

    def touch(self, identifier: str) -> None:
        record = self._must_get(identifier)
        record.lastAccessed = self._clock()
        record.accessCount += 1

    def promote(self, identifier: str, layer: str) -> None:
        record = self._must_get(identifier)
        previous = snapshot(record)
        record.layer = layer
        self._ledger.log(
            identifier,
            "promote",
            self._actor,
            {"previousState": previous, "newState": snapshot(record)},
        )
        self.persist()

    def restore_all(self, records: list[MemoryRecord], seq: int) -> None:
        self._records = {item.id: deepcopy(item) for item in records}
        self.seq = seq
        self.persist()

    def snapshot_all(self) -> dict:
        return {"records": deepcopy(list(self._records.values())), "seq": self.seq}

    def _must_get(self, identifier: str) -> MemoryRecord:
        record = self._records.get(identifier)
        if record is None:
            raise ValueError(f"H-MEM: unknown memory id {identifier}")
        return record

    def classify_domain(self, content: str, tags: list[str], memory_type: str) -> str:
        for tag in tags:
            if tag.startswith("project:"):
                return tag[len("project:") :]
            if tag.startswith("tech:"):
                return "tech"
        tokens = set(tokenize(content))
        best = "general"
        best_score = 0
        for domain, keywords in DOMAIN_KEYWORDS.items():
            score = sum(1 for keyword in keywords if keyword in tokens)
            if domain == "personal" and memory_type in {"personal", "preference"}:
                score += 1
            if score > best_score:
                best = domain
                best_score = score
        return best if best_score > 0 else "general"

    def extract_entities(self, content: str) -> list[str]:
        entities: dict[str, None] = {}
        for token in tokenize(content):
            if token in TECH_TERMS:
                entities[token] = None
        for match in _ENTITY.finditer(content):
            norm = match.group(1).lower()
            if norm not in {"the", "this", "that", "with"}:
                entities[norm] = None
        return list(entities)[: DEFAULTS["entityCap"]]

    def _namespace(self, domain: str, memory_type: str) -> str:
        if memory_type in {"preference", "personal"}:
            bucket = "profile"
        elif memory_type == "factual":
            bucket = "facts"
        else:
            bucket = "notes"
        return f"{domain}/{bucket}"

    def _discover_relationships(self, record: MemoryRecord) -> None:
        for other in self._records.values():
            if len(record.relatedTo) >= DEFAULTS["relatedCap"]:
                break
            shared = [entity for entity in other.entities if entity in record.entities]
            similar = cosine(record.embedding, other.embedding)
            if not record.supersedes and similar > 0.85 and _CORRECTION.search(record.content):
                record.supersedes = other.id
                continue
            if shared and other.domain == record.domain:
                record.relatedTo.append(other.id)
                if (
                    len(other.relatedTo) < DEFAULTS["relatedCap"]
                    and record.id not in other.relatedTo
                ):
                    other.relatedTo.append(record.id)


def snapshot(record: MemoryRecord) -> dict:
    payload = deepcopy(record_to_json(record))
    payload.pop("embedding", None)
    return payload


def record_to_json(record: MemoryRecord) -> dict:
    return asdict(record)


def record_from_json(payload: dict) -> MemoryRecord:
    provenance = payload.get("provenance") or {}
    return MemoryRecord(
        id=payload["id"],
        content=payload["content"],
        type=payload["type"],
        layer=payload["layer"],
        timestamp=payload["timestamp"],
        lastAccessed=payload["lastAccessed"],
        accessCount=payload["accessCount"],
        tags=list(payload.get("tags") or []),
        embedding=list(payload.get("embedding") or []),
        confidence=payload["confidence"],
        source=payload["source"],
        provenance=Provenance(
            origin=provenance.get("origin", "manual"),
            learnedAt=provenance.get("learnedAt", payload.get("timestamp", 0)),
            label=provenance.get("label", payload["source"]),
            refs=provenance.get("refs"),
        ),
        domain=payload.get("domain", "general"),
        namespace=payload.get("namespace", "general/notes"),
        entities=list(payload.get("entities") or []),
        relatedTo=list(payload.get("relatedTo") or []),
        score=payload.get("score"),
        chatId=payload.get("chatId"),
        missionId=payload.get("missionId"),
        goalRunId=payload.get("goalRunId"),
        supersedes=payload.get("supersedes"),
        supersededBy=payload.get("supersededBy"),
        derivedFrom=payload.get("derivedFrom"),
    )


def add_input_from_mapping(payload: dict) -> AddInput:
    provenance = payload.get("provenance")
    if isinstance(provenance, dict):
        provenance = Provenance(
            origin=provenance.get("origin", "manual"),
            learnedAt=provenance.get("learnedAt", 0),
            label=provenance.get("label", payload.get("source", "")),
            refs=provenance.get("refs"),
        )
    return AddInput(
        content=payload["content"],
        source=payload.get("source", ""),
        type=payload.get("type") or "general",
        layer=payload.get("layer") or "working",
        tags=list(payload.get("tags") or []),
        confidence=payload.get("confidence"),
        provenance=provenance,
        chatId=payload.get("chatId"),
        missionId=payload.get("missionId"),
        goalRunId=payload.get("goalRunId"),
        supersedes=payload.get("supersedes"),
        derivedFrom=payload.get("derivedFrom"),
    )
