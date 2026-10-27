"""Optional PostgreSQL snapshot of the in-process H-MEM engine."""

from __future__ import annotations

from dataclasses import asdict

from psycopg.types.json import Jsonb

from alaira_warden.hmem.dreaming import DreamProposal
from alaira_warden.hmem.engine import HMEM
from alaira_warden.hmem.memory_store import record_from_json
from alaira_warden.hmem.trust_ledger import LedgerEntry
from alaira_warden.hmem.types import ConflictRecord


def export_engine(hmem: HMEM) -> dict:
    return {
        "seq": hmem.store.seq,
        "records": [asdict(item) for item in hmem.store.all()],
        "ledger": [asdict(item) for item in hmem.ledger.all()],
        "dreams": [asdict(item) for item in hmem.dreaming.all_proposals()],
        "conflicts": [asdict(item) for item in hmem.conflicts.all()],
    }


def import_engine(hmem: HMEM, payload: dict) -> None:
    records = [record_from_json(item) for item in payload.get("records") or []]
    hmem.store.restore_all(records, payload.get("seq") or 0)
    hmem.ledger.restore([_ledger_from_json(item) for item in payload.get("ledger") or []])
    hmem.dreaming.restore_proposals(
        [_dream_from_json(item) for item in payload.get("dreams") or []]
    )
    hmem.conflicts.restore([_conflict_from_json(item) for item in payload.get("conflicts") or []])


def load_sql(connection, hmem: HMEM) -> bool:
    row = connection.execute("SELECT payload FROM hmem_engine_state WHERE id='default'").fetchone()
    if not row:
        return False
    import_engine(hmem, row["payload"])
    return True


def save_sql(connection, hmem: HMEM) -> None:
    connection.execute(
        "INSERT INTO hmem_engine_state(id, payload) VALUES ('default', %s) "
        "ON CONFLICT (id) DO UPDATE SET payload=EXCLUDED.payload, updated_at=now()",
        (Jsonb(export_engine(hmem)),),
    )


def _ledger_from_json(payload: dict) -> LedgerEntry:
    return LedgerEntry(
        memoryId=payload["memoryId"],
        action=payload["action"],
        actor=payload["actor"],
        timestamp=payload["timestamp"],
        previousState=payload.get("previousState"),
        newState=payload.get("newState"),
        details=payload.get("details"),
    )


def _dream_from_json(payload: dict) -> DreamProposal:
    return DreamProposal(
        id=payload["id"],
        type=payload["type"],
        content=payload["content"],
        derivedFrom=list(payload.get("derivedFrom") or []),
        status=payload.get("status", "proposed"),
        suggestedDomain=payload.get("suggestedDomain"),
    )


def _conflict_from_json(payload: dict) -> ConflictRecord:
    return ConflictRecord(
        id=payload["id"],
        memoryA=payload["memoryA"],
        memoryB=payload["memoryB"],
        reason=payload["reason"],
        confidence=payload["confidence"],
        resolved=payload.get("resolved", False),
        resolution=payload.get("resolution"),
    )
