"""Append-only agent timeline. Summaries never include secrets."""

from datetime import datetime
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from alaira_warden.agents.roster import require_agent
from alaira_warden.db import connect

_STATUSES = frozenset({"started", "decided", "handed_off", "failed", "skipped", "blocked"})


def public_row(row) -> dict:
    payload = dict(row)
    for key, value in payload.items():
        if isinstance(value, UUID):
            payload[key] = str(value)
        elif isinstance(value, datetime):
            payload[key] = value.isoformat()
    return payload


def emit(
    settings,
    *,
    investigation_id,
    agent: str,
    stage: str,
    status: str,
    summary: str,
    run_id=None,
    detail: dict | None = None,
) -> None:
    require_agent(agent)
    if status not in _STATUSES:
        raise ValueError("Unknown agent event status")
    text = " ".join(summary.split())
    if not text or len(text) > 400:
        raise ValueError("Agent summary must be 1 to 400 characters")
    payload = dict(detail or {})
    payload.setdefault("synthetic", False)
    with connect(settings) as connection:
        bound = None
        if run_id:
            found = connection.execute(
                "SELECT id FROM workflow_runs WHERE id=%s", (UUID(str(run_id)),)
            ).fetchone()
            bound = found["id"] if found else None
        connection.execute(
            "INSERT INTO agent_events"
            "(id,investigation_id,run_id,agent,stage,status,summary,detail) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                uuid4(),
                UUID(str(investigation_id)),
                bound,
                agent,
                stage,
                status,
                text,
                Jsonb(payload),
            ),
        )


def for_case(settings, investigation_id, *, limit: int = 80) -> list[dict]:
    with connect(settings) as connection:
        rows = connection.execute(
            "SELECT id,investigation_id,run_id,agent,stage,status,summary,detail,created_at "
            "FROM agent_events WHERE investigation_id=%s "
            "ORDER BY created_at ASC, id ASC LIMIT %s",
            (UUID(str(investigation_id)), min(200, max(1, limit))),
        ).fetchall()
    return [public_row(row) for row in rows]


def recent(settings, *, limit: int = 40) -> list[dict]:
    with connect(settings) as connection:
        rows = connection.execute(
            "SELECT id,investigation_id,run_id,agent,stage,status,summary,detail,created_at "
            "FROM agent_events ORDER BY created_at DESC, id DESC LIMIT %s",
            (min(100, max(1, limit)),),
        ).fetchall()
    return [public_row(row) for row in rows]


def public_recent(settings, *, limit: int = 40) -> list[dict]:
    """Unauthenticated timeline: acts only, no investigation identifiers."""
    events = []
    for row in recent(settings, limit=limit):
        detail = row.get("detail") or {}
        events.append(
            {
                "agent": row["agent"],
                "stage": row["stage"],
                "status": row["status"],
                "summary": row["summary"],
                "created_at": row["created_at"],
                "synthetic": bool(detail.get("synthetic")),
            }
        )
    return events
