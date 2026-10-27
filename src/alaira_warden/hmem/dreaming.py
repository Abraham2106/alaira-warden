"""Dreaming: proposals never auto-materialize."""

from __future__ import annotations

from alaira_warden.hmem.embeddings import cosine, jaccard
from alaira_warden.hmem.memory_store import MemoryStoreService
from alaira_warden.hmem.trust_ledger import TrustLedgerService
from alaira_warden.hmem.types import DEFAULTS, ClockFn, DreamProposal, MemoryRecord


class DreamingService:
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
        self._proposals: dict[str, DreamProposal] = {}
        self.seq = 0

    def _relatedness(self, left: MemoryRecord, right: MemoryRecord) -> float:
        return (
            0.5 * max(0.0, cosine(left.embedding, right.embedding))
            + 0.2 * jaccard(left.tags, right.tags)
            + 0.1 * (1 if left.domain == right.domain else 0)
            + 0.2 * jaccard(left.entities, right.entities)
        )

    def _cluster(self) -> list[list[MemoryRecord]]:
        all_records = self._store.all()
        used: set[str] = set()
        clusters: list[list[MemoryRecord]] = []
        for seed in all_records:
            if seed.id in used:
                continue
            group = [seed]
            for other in all_records:
                if other.id == seed.id or other.id in used:
                    continue
                if self._relatedness(seed, other) >= DEFAULTS["dreamRelatedness"]:
                    group.append(other)
            if len(group) >= DEFAULTS["dreamClusterMinSize"]:
                for member in group:
                    used.add(member.id)
                clusters.append(group)
        return clusters

    def dream(self) -> list[DreamProposal]:
        created: list[DreamProposal] = []

        def propose(payload: dict) -> None:
            self.seq += 1
            proposal = DreamProposal(
                id=f"dream-{self.seq}",
                type=payload["type"],
                content=payload["content"],
                derivedFrom=list(payload["derivedFrom"]),
                status="proposed",
                suggestedDomain=payload.get("suggestedDomain"),
            )
            self._proposals[proposal.id] = proposal
            created.append(proposal)
            self._ledger.log(
                proposal.id,
                "dream_proposed",
                self._actor,
                {"details": {"type": payload["type"], "derivedFrom": payload["derivedFrom"]}},
            )

        insights = 0
        for cluster in self._cluster():
            if insights >= DEFAULTS["maxDreamProposalsPerType"]:
                break
            domains = "/".join(dict.fromkeys(item.domain for item in cluster))
            propose(
                {
                    "type": "insight",
                    "content": (
                        f"Across {len(cluster)} related memories ({domains}): "
                        + " + ".join(item.content for item in cluster)
                    ),
                    "derivedFrom": [item.id for item in cluster],
                }
            )
            insights += 1

        domains = 0
        for memory in self._store.all():
            if domains >= DEFAULTS["maxDreamProposalsPerType"]:
                break
            if memory.domain != "general":
                continue
            suggested = self._store.classify_domain(memory.content, memory.tags, memory.type)
            if suggested != "general":
                propose(
                    {
                        "type": "domain",
                        "content": f'Reclassify "{memory.content[:60]}" as {suggested}',
                        "derivedFrom": [memory.id],
                        "suggestedDomain": suggested,
                    }
                )
                domains += 1

        invariants = 0
        prefs = [
            item
            for item in self._store.all()
            if item.type in {"preference", "personal"} or "event:user_correction" in item.tags
        ]
        by_domain: dict[str, list[MemoryRecord]] = {}
        for item in prefs:
            by_domain.setdefault(item.domain, []).append(item)
        for domain, group in by_domain.items():
            if invariants >= DEFAULTS["maxDreamProposalsPerType"]:
                break
            if len(group) < 2:
                continue
            propose(
                {
                    "type": "invariant",
                    "content": (
                        f"Stable pattern in {domain}: " + "; ".join(item.content for item in group)
                    ),
                    "derivedFrom": [item.id for item in group],
                }
            )
            invariants += 1
        return created

    def pending(self) -> list[DreamProposal]:
        return [item for item in self._proposals.values() if item.status == "proposed"]

    def approve(self, proposal_id: str) -> MemoryRecord | None:
        proposal = self._proposals.get(proposal_id)
        if proposal is None or proposal.status != "proposed":
            raise ValueError(f"H-MEM: no pending proposal {proposal_id}")
        proposal.status = "approved"
        self._ledger.log(
            proposal_id, "dream_approved", self._actor, {"details": {"type": proposal.type}}
        )
        if proposal.type == "domain":
            for identifier in proposal.derivedFrom:
                memory = self._store.get(identifier)
                if memory and proposal.suggestedDomain:
                    self._store.update(identifier, {"domain": proposal.suggestedDomain})
            return None
        return self._store.add(
            {
                "content": proposal.content,
                "type": "factual" if proposal.type == "insight" else "preference",
                "layer": "long_term",
                "tags": [f"dream:{proposal.type}"],
                "confidence": 0.75,
                "source": "dreaming",
                "provenance": {
                    "origin": "dream",
                    "learnedAt": self._clock(),
                    "label": f"approved {proposal.type} proposal",
                },
                "derivedFrom": proposal.derivedFrom,
            }
        )

    def reject(self, proposal_id: str) -> None:
        proposal = self._proposals.get(proposal_id)
        if proposal is None or proposal.status != "proposed":
            raise ValueError(f"H-MEM: no pending proposal {proposal_id}")
        proposal.status = "rejected"
        self._ledger.log(
            proposal_id, "dream_rejected", self._actor, {"details": {"type": proposal.type}}
        )

    def all_proposals(self) -> list[DreamProposal]:
        return list(self._proposals.values())

    def restore_proposals(self, proposals: list[DreamProposal]) -> None:
        self._proposals = {item.id: item for item in proposals}
        self.seq = max((int(item.id.split("-")[1]) for item in proposals), default=0)
