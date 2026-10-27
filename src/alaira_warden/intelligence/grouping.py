"""Group records by shared identifiers. Titles are never a join key.

A connected component is one report lineage. Several catalogs repeating the same
CVE or GHSA are not independent corroborations (RN-03), so the evidence class stays
``preliminary`` rather than ``confirmed``. This module does not emit ``confirmed``.

An identifier is ambiguous when the records that carry it also carry two or more
different identifiers of another family (for example one CVE shared by two GHSA
ids). The records stay in one group and the identifier is declared.

Revisions are members with the same source and source id and different content
hashes. They are kept. A status change inside those revisions is history. The same
disagreement across different records is contradictory.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from alaira_warden.intelligence.models import (
    AdvisoryGroup,
    GroupingResult,
    IdentifierLink,
    MemberRevision,
    SourceRecord,
)
from alaira_warden.intelligence.textutil import canonical_identifier


def group_advisories(records: Sequence[SourceRecord]) -> GroupingResult:
    if not records:
        return GroupingResult(groups=[], warnings=[])
    parent = list(range(len(records)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    owners: dict[str, list[int]] = {}
    identities = [_identifiers(record) for record in records]
    for index, found in enumerate(identities):
        for identifier in found:
            owners.setdefault(identifier, []).append(index)
    for indexes in owners.values():
        for other in indexes[1:]:
            union(indexes[0], other)

    buckets: dict[int, list[int]] = {}
    for index in range(len(records)):
        buckets.setdefault(find(index), []).append(index)

    groups: list[AdvisoryGroup] = []
    for indexes in buckets.values():
        members = [records[index] for index in indexes]
        groups.append(_group(members))
    groups.sort(key=lambda item: item.group_id)
    return GroupingResult(groups=groups, warnings=[])


def _identifiers(record: SourceRecord) -> list[str]:
    found: list[str] = []
    for value in [record.source_id, *record.aliases]:
        identifier = canonical_identifier(value)
        if identifier and identifier not in found:
            found.append(identifier)
    return found


def _family(identifier: str) -> str:
    if identifier.startswith("CVE-"):
        return "CVE"
    if identifier.startswith("GHSA-"):
        return "GHSA"
    return "OTHER"


def _member_key(record: SourceRecord) -> str:
    return f"{record.source}|{record.source_id}|{record.content_hash}"


def _ambiguous(members: Sequence[SourceRecord]) -> list[str]:
    by_identifier: dict[str, list[SourceRecord]] = {}
    for member in members:
        for identifier in _identifiers(member):
            by_identifier.setdefault(identifier, []).append(member)
    found: list[str] = []
    for identifier, group in by_identifier.items():
        if len(group) < 2:
            continue
        families: dict[str, set[str]] = {}
        for member in group:
            for other in _identifiers(member):
                if other == identifier:
                    continue
                families.setdefault(_family(other), set()).add(other)
        if any(len(values) > 1 for values in families.values()):
            found.append(identifier)
    return sorted(found)


def _negative(status: str | None) -> bool:
    if not status:
        return False
    text = status.casefold()
    return "reject" in text or "withdraw" in text


def _explicit_active(record: SourceRecord) -> bool:
    if _negative(record.source_status):
        return False
    if record.source == "github" and record.advisory_kind in {"reviewed", "malware", "unreviewed"}:
        return True
    if record.source == "nvd" and bool(record.source_status):
        return True
    return record.source == "osv" and record.source_status == "published"


def _thin(record: SourceRecord) -> bool:
    return "detail_not_loaded" in record.warnings and not record.summary and not record.affected


def _assess(
    members: Sequence[SourceRecord], ambiguous: Sequence[str]
) -> tuple[str, str, list[str]]:
    warnings: list[str] = []
    if members and all(_thin(member) for member in members):
        return (
            "insufficient",
            "Only identifiers were retrieved; the advisory detail is not loaded.",
            ["detail_not_loaded"],
        )
    sources = {member.source for member in members}
    if len(sources) > 1:
        warnings.append("shared_identifiers_are_not_independent_corroboration")
    if any(_thin(member) for member in members):
        warnings.append("detail_not_loaded")
    negative = [member for member in members if _negative(member.source_status)]
    active = [member for member in members if _explicit_active(member)]
    if negative and active:
        negative_keys = {(member.source, member.source_id) for member in negative}
        active_keys = {(member.source, member.source_id) for member in active}
        if negative_keys == active_keys:
            warnings.append("status_changed_across_revisions")
        else:
            warnings.append("status_disagreement")
            return (
                "contradictory",
                "Records disagree on a withdrawn or rejected status.",
                warnings,
            )
    if ambiguous:
        warnings.append("ambiguous_identifier")
    if len(sources) > 1:
        justification = (
            "Records share verifiable identifiers. Repeated catalogs are one report "
            "lineage, not independent corroboration, so the evidence stays preliminary."
        )
    else:
        justification = "A single uncorroborated source stays preliminary."
    if ambiguous:
        justification += " An identifier links distinct ids of the same family and is ambiguous."
    return "preliminary", justification, warnings


def _group(members: Sequence[SourceRecord]) -> AdvisoryGroup:
    ordered = sorted(members, key=lambda record: (record.source, record.source_id,
        record.content_hash))
    identifiers: list[str] = []
    for member in ordered:
        for identifier in _identifiers(member):
            if identifier not in identifiers:
                identifiers.append(identifier)
    ambiguous = _ambiguous(ordered)
    links: list[IdentifierLink] = []
    owners: dict[str, list[str]] = {}
    for member in ordered:
        for identifier in _identifiers(member):
            owners.setdefault(identifier, [])
            key = _member_key(member)
            if key not in owners[identifier]:
                owners[identifier].append(key)
    for identifier in sorted(owners):
        links.append(
            IdentifierLink(
                identifier=identifier,
                members=owners[identifier],
                ambiguous=identifier in ambiguous,
            )
        )
    revisions: dict[str, list[MemberRevision]] = {}
    grouped: dict[str, list[SourceRecord]] = {}
    for member in ordered:
        grouped.setdefault(f"{member.source}|{member.source_id}", []).append(member)
    for key, revisions_of in grouped.items():
        if len({item.content_hash for item in revisions_of}) < 2:
            continue
        revisions[key] = [
            MemberRevision(
                source=item.source,
                source_id=item.source_id,
                content_hash=item.content_hash,
                modified_at=item.modified_at,
                retrieved_at=item.retrieved_at,
            )
            for item in sorted(
                revisions_of,
                key=lambda item: (
                    item.modified_at or item.retrieved_at,
                    item.content_hash,
                ),
            )
        ]
    evidence_class, justification, warnings = _assess(ordered, ambiguous)
    if identifiers:
        basis = "\n".join(sorted(identifiers))
    else:
        basis = "\n".join(_member_key(item) for item in ordered)
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
    return AdvisoryGroup(
        group_id=f"grp_{digest}",
        identifiers=sorted(identifiers),
        members=list(ordered),
        links=links,
        ambiguous_identifiers=list(ambiguous),
        revisions=revisions,
        independent_report_count=1 if ordered else 0,
        evidence_class=evidence_class,  # type: ignore[arg-type]
        justification=justification,
        warnings=warnings,
    )
