"""Grouping, manual intake, and persistence without a database."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from alaira_warden.intelligence import (
    SourceError,
    consultation_report,
    content_hash,
    default_sync_plan,
    group_advisories,
    manual_advisory,
    persist_records,
)
from alaira_warden.intelligence.github import normalize_github_advisory
from alaira_warden.intelligence.models import Attribution, SourceBatch, SourceRecord
from alaira_warden.intelligence.nvd import normalize_nvd_cve
from alaira_warden.intelligence.osv import normalize_osv_vulnerability

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
_ATTRIBUTION = Attribution(
    provider="test", documentation_url="https://example.com/docs", notes="test"
)


def _manual_record(
    source, source_id, *, title, aliases=None, status=None, kind=None, warnings=None, digest="a"
):
    origin = {"id": source_id, "digest": digest, "title": title}
    return SourceRecord(
        source=source,
        source_id=source_id,
        aliases=aliases or [],
        title=title,
        summary=title,
        source_url=f"https://example.com/{source_id}",
        retrieved_at=NOW,
        content_hash=content_hash(origin),
        attribution=_ATTRIBUTION,
        origin=origin,
        warnings=warnings or [],
        advisory_kind=kind,
        source_status=status,
    )


def test_aliases_group_records_and_titles_do_not():
    github, _warning = normalize_github_advisory(
        {
            "ghsa_id": "GHSA-abcd-efgh-ijkl",
            "summary": "Same title",
            "type": "reviewed",
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-abcd-efgh-ijkl"},
                {"type": "CVE", "value": "CVE-2024-1111"},
            ],
        },
        retrieved_at=NOW,
    )
    osv, _warning = normalize_osv_vulnerability(
        {
            "id": "GHSA-abcd-efgh-ijkl",
            "summary": "Same title",
            "details": "Copied from GitHub",
            "aliases": ["CVE-2024-1111"],
            "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}, "ranges": []}],
        },
        retrieved_at=NOW,
    )
    nvd, _warning = normalize_nvd_cve(
        {
            "cve": {
                "id": "CVE-2024-1111",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Same title"}],
            }
        },
        retrieved_at=NOW,
    )
    other = _manual_record("osv", "OSV-unrelated", title="Same title")
    result = group_advisories([github, osv, nvd, other])
    assert len(result.groups) == 2
    grouped = next(group for group in result.groups if len(group.members) == 3)
    assert grouped.independent_report_count == 1
    assert grouped.evidence_class == "preliminary"
    assert "shared_identifiers_are_not_independent_corroboration" in grouped.warnings
    assert all(group.evidence_class != "confirmed" for group in result.groups)
    assert {member.source for member in grouped.members} == {"github", "osv", "nvd"}


def test_revisions_stay_and_ambiguous_identifiers_are_declared():
    first, _warning = normalize_github_advisory(
        {
            "ghsa_id": "GHSA-aaaa-aaaa-aaaa",
            "summary": "First wording",
            "type": "reviewed",
            "updated_at": "2024-01-01T00:00:00Z",
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-aaaa-aaaa-aaaa"},
                {"type": "CVE", "value": "CVE-2024-2222"},
            ],
        },
        retrieved_at=NOW,
    )
    second, _warning = normalize_github_advisory(
        {
            "ghsa_id": "GHSA-aaaa-aaaa-aaaa",
            "summary": "Revised wording",
            "type": "reviewed",
            "updated_at": "2024-06-01T00:00:00Z",
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-aaaa-aaaa-aaaa"},
                {"type": "CVE", "value": "CVE-2024-2222"},
            ],
        },
        retrieved_at=NOW,
    )
    other, _warning = normalize_github_advisory(
        {
            "ghsa_id": "GHSA-bbbb-bbbb-bbbb",
            "summary": "Different advisory, same CVE text",
            "type": "reviewed",
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-bbbb-bbbb-bbbb"},
                {"type": "CVE", "value": "CVE-2024-2222"},
            ],
        },
        retrieved_at=NOW,
    )
    result = group_advisories([first, second, other])
    assert len(result.groups) == 1
    group = result.groups[0]
    assert len(group.members) == 3
    assert len(group.revisions["github|GHSA-aaaa-aaaa-aaaa"]) == 2
    assert "CVE-2024-2222" in group.ambiguous_identifiers
    assert "GHSA-aaaa-aaaa-aaaa" not in group.ambiguous_identifiers


def test_withdrawn_disagreement_is_contradictory_and_revisions_are_history():
    rejected, _warning = normalize_nvd_cve(
        {"cve": {"id": "CVE-2024-3333", "vulnStatus": "Rejected"}},
        retrieved_at=NOW,
    )
    reviewed, _warning = normalize_github_advisory(
        {
            "ghsa_id": "GHSA-cccc-cccc-cccc",
            "type": "reviewed",
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-cccc-cccc-cccc"},
                {"type": "CVE", "value": "CVE-2024-3333"},
            ],
        },
        retrieved_at=NOW,
    )
    conflict = group_advisories([rejected, reviewed]).groups[0]
    assert conflict.evidence_class == "contradictory"
    old, _warning = normalize_github_advisory(
        {
            "ghsa_id": "GHSA-dddd-dddd-dddd",
            "type": "reviewed",
            "updated_at": "2024-01-01T00:00:00Z",
        },
        retrieved_at=NOW,
    )
    new, _warning = normalize_github_advisory(
        {
            "ghsa_id": "GHSA-dddd-dddd-dddd",
            "type": "reviewed",
            "withdrawn_at": "2024-06-01T00:00:00Z",
            "updated_at": "2024-06-01T00:00:00Z",
        },
        retrieved_at=NOW,
    )
    history = group_advisories([old, new]).groups[0]
    assert history.evidence_class == "preliminary"
    assert "status_changed_across_revisions" in history.warnings


def test_identifier_only_group_is_insufficient():
    partial, _warning = normalize_osv_vulnerability(
        {"id": "GHSA-eeee-eeee-eeee", "modified": "2024-01-01T00:00:00Z"},
        retrieved_at=NOW,
    )
    group = group_advisories([partial]).groups[0]
    assert group.evidence_class == "insufficient"


def test_manual_advisory_without_cve_and_consultation():
    record = manual_advisory(
        source_url="https://example.com/incident",
        description="Build server pulled a bad package.",
        received_at=NOW,
        title="No CVE yet",
        retrieved_at=NOW,
    )
    assert record.source == "manual"
    assert record.aliases == []
    assert record.known_exploited is None
    assert record.received_at == NOW
    assert not record.source_id.startswith("CVE-")
    plan = default_sync_plan()
    assert {item.source for item in plan} == {"github", "osv", "nvd", "cisa-kev"}
    report = consultation_report(
        batches=[
            SourceBatch(
                source="osv",
                retrieved_at=NOW,
                records=[],
                complete=True,
                warnings=["empty_result_is_not_absence_of_risk"],
            )
        ],
        errors=[
            SourceError(category="timeout", source="nvd", operation="get_cve", reason="timeout")
        ],
    )
    assert report.attempts[1].ok is False
    assert report.attempts[1].error_category == "timeout"
    assert any("not evidence" in item for item in report.unverified)


class _Cursor:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _Connection:
    def __init__(self):
        self.statements = []
        self.advisories = {}
        self.revisions = set()

    def execute(self, query, params=None):
        self.statements.append((query, params))
        if "INSERT INTO advisories" in query:
            key = (params[1], params[2])
            self.advisories.setdefault(key, params[0])
            return _Cursor((self.advisories[key],))
        if "INSERT INTO advisory_revisions" in query:
            key = (params[1], params[2])
            if key in self.revisions:
                return _Cursor(None)
            self.revisions.add(key)
            return _Cursor((params[0],))
        raise AssertionError(query)


def test_persist_is_idempotent_and_does_not_create_tables():
    record = manual_advisory(
        source_url="https://example.com/incident",
        description="No database is opened by this test.",
        received_at=NOW,
        retrieved_at=NOW,
    )
    connection = _Connection()
    first = persist_records(connection, [record])
    second = persist_records(connection, [record])
    assert first.inserted_revisions == 1
    assert second.unchanged_revisions == 1
    assert second.inserted_revisions == 0
    sql = "\n".join(statement for statement, _params in connection.statements)
    assert "CREATE TABLE" not in sql
    assert "DROP " not in sql
    payload = json.loads(connection.statements[1][1][3])
    assert payload["source"] == "manual"
    assert payload["content_hash"] == record.content_hash
