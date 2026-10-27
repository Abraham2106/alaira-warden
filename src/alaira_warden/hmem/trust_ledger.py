"""Append-only trust ledger. Entries are never mutated or deleted."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from alaira_warden.hmem.types import ClockFn, LedgerEntry, MemoryRecord


class TrustLedgerService:
    def __init__(self, clock: ClockFn, persist_dir: str | None = None):
        self._clock = clock
        self._entries: list[LedgerEntry] = []
        self._file: Path | None = None
        if persist_dir:
            directory = Path(persist_dir)
            directory.mkdir(parents=True, exist_ok=True)
            self._file = directory / "ledger.jsonl"
            if self._file.exists():
                self._entries = [
                    _entry_from_json(json.loads(line))
                    for line in self._file.read_text(encoding="utf-8").splitlines()
                    if line
                ]

    def log(
        self,
        memory_id: str,
        action: str,
        actor: str,
        extra: dict[str, Any] | None = None,
    ) -> LedgerEntry:
        payload = extra or {}
        entry = LedgerEntry(
            memoryId=memory_id,
            action=action,
            actor=actor,
            timestamp=self._clock(),
            previousState=payload.get("previousState"),
            newState=payload.get("newState"),
            details=payload.get("details"),
        )
        self._entries.append(entry)
        if self._file:
            with self._file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(_entry_to_json(entry), ensure_ascii=False) + "\n")
        return entry

    def history(self, memory_id: str) -> list[LedgerEntry]:
        return [entry for entry in self._entries if entry.memoryId == memory_id]

    def all(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    def stats(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for entry in self._entries:
            out[entry.action] = out.get(entry.action, 0) + 1
        return out

    def restore(self, entries: list[LedgerEntry]) -> None:
        self._entries = list(entries)


def snapshot(record: MemoryRecord) -> dict[str, Any]:
    copied = _record_to_json(record)
    copied.pop("embedding", None)
    return copied


def _record_to_json(record: MemoryRecord) -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(record)


def _entry_to_json(entry: LedgerEntry) -> dict[str, Any]:
    from dataclasses import asdict

    payload = asdict(entry)
    return {key: value for key, value in payload.items() if value is not None}


def _entry_from_json(payload: dict[str, Any]) -> LedgerEntry:
    return LedgerEntry(
        memoryId=payload["memoryId"],
        action=payload["action"],
        actor=payload["actor"],
        timestamp=payload["timestamp"],
        previousState=payload.get("previousState"),
        newState=payload.get("newState"),
        details=payload.get("details"),
    )
