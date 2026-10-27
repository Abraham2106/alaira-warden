"""Warden product mapping. Recall is fail-open and never assigns exposure."""

from __future__ import annotations

from dataclasses import asdict
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from alaira_warden.hmem.engine import HMEM
from alaira_warden.hmem.persist import load_sql, save_sql
from alaira_warden.hmem.types import QueryResult


def query_to_payload(result: QueryResult) -> dict:
    return {
        "engine": "hmem",
        "context": result.context,
        "trace": result.trace,
        "memories": [
            {
                "id": item.memory.id,
                "content": item.memory.content,
                "source": item.memory.source,
                "confidence": item.memory.confidence,
                "layer": item.memory.layer,
                "type": item.memory.type,
                "relevance": item.relevance,
                "supersededBy": item.memory.supersededBy,
            }
            for item in result.memories
        ],
    }


def empty_recall(query: str, reason: str) -> dict:
    return {
        "engine": "hmem",
        "query": query,
        "context": "",
        "trace": {"retrievalReason": reason, "strategy": "minimal", "scores": {}},
        "memories": [],
        "available": False,
    }


class InvestigationMemory:
    def __init__(self, hmem: HMEM):
        self.hmem = hmem

    def hydrate(self, connection) -> None:
        try:
            load_sql(connection, self.hmem)
        except Exception:
            return

    def flush(self, connection) -> None:
        try:
            save_sql(connection, self.hmem)
        except Exception:
            return

    def remember(self, payload: dict) -> str | None:
        try:
            record = self.hmem.add(payload)
        except Exception:
            return None
        return record.id

    def recall(self, query: str, opts: dict | None = None) -> dict:
        try:
            result = self.hmem.query(query, opts)
        except Exception as error:
            return empty_recall(query, f"hmem_unavailable:{error.__class__.__name__}")
        payload = query_to_payload(result)
        payload["query"] = query
        payload["available"] = True
        return payload

    def recall_for_cases(self, query: str, investigation_ids, opts: dict | None = None) -> dict:
        """Caller supplies server-authorized case ids; unscoped memories stay excluded."""
        return self.recall(query, {**(opts or {}), "allowedChatIds": list(investigation_ids)})

    def remember_source(self, record, investigation_id: UUID, advisory: str) -> None:
        packages = ", ".join(
            f"{item.package_name}@{item.ecosystem}" for item in record.affected if item.package_name
        )
        summary = (record.summary or record.title or record.source_id)[:300]
        content = (
            f"{record.source} {record.source_id} should be remembered for {advisory}"
            f"{f' because it names {packages}' if packages else ''}: {summary}"
        )
        self.remember(
            {
                "content": content,
                "type": "factual",
                "layer": "working",
                "tags": ["advisory", record.source, advisory],
                "confidence": 0.7,
                "source": record.source_url or f"source:{record.source}:{record.source_id}",
                "chatId": str(investigation_id),
                "provenance": {
                    "origin": "document",
                    "learnedAt": self.hmem.clock(),
                    "label": f"{record.source}:{record.source_id}",
                },
            }
        )

    def remember_assessment(
        self, assessment, investigation_id: UUID, advisory: str, revision: str
    ) -> None:
        findings = assessment.findings[:8]
        names = ", ".join(
            f"{item.package_name} {item.resolved_version}"
            for item in findings
            if getattr(item, "package_name", None)
        )
        reasons = "; ".join(
            ", ".join(item.reasons) for item in findings if getattr(item, "reasons", None)
        )
        content = (
            f"Assessment of {advisory} decided {assessment.exposure} for {names or 'components'} "
            f"because {reasons or 'explicit_version_evaluation'}"
        )
        self.remember(
            {
                "content": content[:300],
                "type": "factual",
                "layer": "working",
                "tags": ["assessment", advisory, assessment.exposure],
                "confidence": 0.8,
                "source": f"assessment:{revision}",
                "chatId": str(investigation_id),
                "provenance": {
                    "origin": "plan_completion",
                    "learnedAt": self.hmem.clock(),
                    "label": f"correlation:{advisory}",
                },
            }
        )

    def save_recall(self, connection, investigation_id, run_id, payload: dict) -> None:
        connection.execute(
            "INSERT INTO hmem_recalls(id, investigation_id, run_id, query, payload) "
            "VALUES (%s,%s,%s,%s,%s)",
            (
                uuid4(),
                investigation_id,
                run_id,
                payload.get("query") or "",
                Jsonb(payload),
            ),
        )

    def latest_recall(self, connection, investigation_id) -> dict | None:
        row = connection.execute(
            "SELECT payload FROM hmem_recalls WHERE investigation_id=%s "
            "ORDER BY created_at DESC, id DESC LIMIT 1",
            (investigation_id,),
        ).fetchone()
        return row["payload"] if row else None

    def public_state(self) -> dict:
        return {
            "engine": "hmem",
            "records": len(self.hmem.store.all()),
            "ledger": dict(self.hmem.ledger.stats()),
            "pending_dreams": len(self.hmem.dreaming.pending()),
            "open_conflicts": len(self.hmem.conflicts.queue()),
        }

    def dump_record(self, identifier: str) -> dict | None:
        record = self.hmem.store.get(identifier)
        if record is None:
            return None
        payload = asdict(record)
        payload.pop("embedding", None)
        return payload
