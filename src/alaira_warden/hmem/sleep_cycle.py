"""Sleep cycle. preview() mutates nothing; execute() backups first."""

from __future__ import annotations

from alaira_warden.hmem.embeddings import cosine
from alaira_warden.hmem.memory_store import MemoryStoreService
from alaira_warden.hmem.trust_ledger import TrustLedgerService
from alaira_warden.hmem.types import (
    DAY_MS,
    DEFAULTS,
    ClockFn,
    SleepPreview,
    SleepReport,
)

HUB_THRESHOLD = 3


class SleepCycleService:
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
        self._backups: dict[str, dict] = {}
        self.backup_seq = 0

    def preview(self) -> SleepPreview:
        now = self._clock()
        all_records = self._store.all()
        referenced: set[str] = set()
        for memory in all_records:
            referenced.update(memory.relatedTo)
            if memory.supersedes:
                referenced.add(memory.supersedes)
            referenced.update(memory.derivedFrom or [])

        to_consolidate = [
            memory.id
            for memory in all_records
            if memory.layer == "short_term"
            and now - memory.lastAccessed >= DEFAULTS["consolidationDays"] * DAY_MS
        ]
        to_archive = []
        for memory in all_records:
            old_enough = now - memory.timestamp >= DEFAULTS["archiveMinDays"] * DAY_MS
            low_access = memory.accessCount <= DEFAULTS["archiveMaxAccess"]
            unreferenced = memory.id not in referenced
            if not (old_enough and low_access and unreferenced):
                continue
            if memory.supersedes:
                continue
            if memory.derivedFrom:
                continue
            if len(memory.relatedTo) >= HUB_THRESHOLD:
                continue
            to_archive.append(memory.id)

        to_synthesize: list[list[str]] = []
        used: set[str] = set()
        for i, first in enumerate(all_records):
            if first.id in used:
                continue
            group = [first]
            for other in all_records[i + 1 :]:
                if other.id in used:
                    continue
                if cosine(first.embedding, other.embedding) >= DEFAULTS["synthesisCosine"]:
                    group.append(other)
            if len(group) >= 2:
                for member in group:
                    used.add(member.id)
                to_synthesize.append([member.id for member in group])
        return SleepPreview(
            toConsolidate=to_consolidate, toArchive=to_archive, toSynthesize=to_synthesize
        )

    def execute(self, preview: SleepPreview | None = None) -> SleepReport:
        plan = preview or self.preview()
        self.backup_seq += 1
        backup_id = f"backup-{self.backup_seq}"
        self._backups[backup_id] = self._store.snapshot_all()
        action_log = [f"backup {backup_id} created"]

        for identifier in plan.toConsolidate:
            if self._store.get(identifier) is None:
                continue
            self._store.promote(identifier, "long_term")
            self._ledger.log(
                identifier,
                "sleep_consolidate",
                self._actor,
                {"details": {"from": "short_term", "to": "long_term"}},
            )
            action_log.append(f"consolidated {identifier}")

        for identifier in plan.toArchive:
            memory = self._store.get(identifier)
            if memory is None:
                continue
            self._ledger.log(
                identifier,
                "sleep_archive",
                self._actor,
                {
                    "details": {
                        "age": self._clock() - memory.timestamp,
                        "accessCount": memory.accessCount,
                    }
                },
            )
            self._store.delete(identifier, "sleep archive")
            action_log.append(f"archived {identifier}")

        synthesized = 0
        for group in plan.toSynthesize:
            members = [item for identifier in group if (item := self._store.get(identifier))]
            if len(members) < 2:
                continue
            merged = self._store.add(
                {
                    "content": "Synthesis: " + " | ".join(item.content for item in members),
                    "type": "factual",
                    "layer": "long_term",
                    "tags": list(dict.fromkeys(tag for item in members for tag in item.tags)),
                    "confidence": max(item.confidence for item in members),
                    "source": "sleep:synthesis",
                    "provenance": {
                        "origin": "sleep_synthesis",
                        "learnedAt": self._clock(),
                        "label": f"synthesized from {len(members)} memories",
                    },
                    "derivedFrom": [item.id for item in members],
                }
            )
            self._ledger.log(
                merged.id, "sleep_synthesize", self._actor, {"details": {"sources": group}}
            )
            for member in members:
                self._store.delete(member.id, "merged by sleep synthesis")
            synthesized += 1
            action_log.append(f"synthesized {merged.id} from {', '.join(group)}")

        self._store.persist()
        return SleepReport(
            backupId=backup_id,
            consolidated=len(plan.toConsolidate),
            archived=len(plan.toArchive),
            synthesized=synthesized,
            actionLog=action_log,
        )

    def restore(self, backup_id: str) -> None:
        backup = self._backups.get(backup_id)
        if backup is None:
            raise ValueError(f"H-MEM: unknown backup {backup_id}")
        self._store.restore_all(backup["records"], backup["seq"])
        self._ledger.log("*", "restore", self._actor, {"details": {"backupId": backup_id}})
