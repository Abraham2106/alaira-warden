"""Write advisories through a connection the caller owns.

Importing this module does not connect to PostgreSQL or create tables. The SQL
targets the existing ``advisories`` and ``advisory_revisions`` tables. The caller
commits. A new content hash inserts a revision; the same hash is left unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import uuid4

from alaira_warden.intelligence.models import SourceRecord

_UPSERT_ADVISORY = """
INSERT INTO advisories (id, source, source_identifier, aliases)
VALUES (%s, %s, %s, %s::jsonb)
ON CONFLICT (source, source_identifier)
DO UPDATE SET aliases = EXCLUDED.aliases
RETURNING id
"""

_INSERT_REVISION = """
INSERT INTO advisory_revisions (
    id, advisory_id, content_hash, payload, published_at, retrieved_at
)
VALUES (%s, %s, %s, %s::jsonb, %s, %s)
ON CONFLICT (advisory_id, content_hash) DO NOTHING
RETURNING id
"""


class SqlConnection(Protocol):
    def execute(self, query: str, params: Sequence[Any] | None = None) -> Any: ...


@dataclass(frozen=True)
class PersistResult:
    advisories: int
    inserted_revisions: int
    unchanged_revisions: int


def persist_records(connection: SqlConnection, records: Sequence[SourceRecord]) -> PersistResult:
    """Upsert records. ``connection.execute`` must return an object with ``fetchone``."""

    inserted = 0
    unchanged = 0
    seen: set[tuple[str, str]] = set()
    for record in records:
        advisory_id = _advisory_id(connection, record)
        seen.add((record.source, record.source_id))
        payload = json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        revision = connection.execute(
            _INSERT_REVISION,
            (
                str(uuid4()),
                advisory_id,
                record.content_hash,
                payload,
                record.published_at,
                record.retrieved_at,
            ),
        )
        row = revision.fetchone()
        if row is None:
            unchanged += 1
        else:
            inserted += 1
    return PersistResult(
        advisories=len(seen),
        inserted_revisions=inserted,
        unchanged_revisions=unchanged,
    )


def _advisory_id(connection: SqlConnection, record: SourceRecord) -> str:
    cursor = connection.execute(
        _UPSERT_ADVISORY,
        (
            str(uuid4()),
            record.source,
            record.source_id,
            json.dumps(record.aliases, separators=(",", ":")),
        ),
    )
    row = cursor.fetchone()
    if row is None:
        raise RuntimeError("advisory upsert did not return an id")
    identifier = row["id"] if isinstance(row, dict) else row[0]
    if identifier is None:
        raise RuntimeError("advisory upsert did not return an id")
    return str(identifier)
