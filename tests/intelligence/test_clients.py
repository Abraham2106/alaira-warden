"""Offline client tests for GitHub, OSV, NVD, and CISA KEV."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from alaira_warden.intelligence import (
    SourceError,
    WorkBudget,
    content_hash,
    fetch_github_advisories,
    fetch_github_advisory,
    fetch_kev_catalog,
    fetch_nvd_cve,
    fetch_nvd_modified,
    lookup_kev,
    query_osv,
    query_osv_batch,
)
from alaira_warden.intelligence.http import HttpRequest, HttpResponse

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)


class ScriptTransport:
    def __init__(self, items):
        self.items = list(items)
        self.requests: list[HttpRequest] = []

    def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        item = self.items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def response(status: int, payload, headers=None) -> HttpResponse:
    if isinstance(payload, bytes):
        body = payload
    else:
        body = json.dumps(payload).encode("utf-8")
    return HttpResponse(
        status,
        {key.lower(): value for key, value in (headers or {}).items()},
        body,
    )


def pause(bucket: list[float]):
    return lambda seconds: bucket.append(seconds)

SECRET = "super-secret-token"
PRIVATE = "internal-db-password"


def _ghsa(**extra):
    payload = {
        "ghsa_id": "GHSA-abcd-efgh-ijkl",
        "summary": "Prototype pollution",
        "description": "Details",
        "type": "reviewed",
        "severity": "high",
        "html_url": "https://github.com/advisories/GHSA-abcd-efgh-ijkl",
        "published_at": "2024-01-02T03:04:05Z",
        "updated_at": "2024-02-02T03:04:05Z",
        "identifiers": [
            {"type": "GHSA", "value": "GHSA-abcd-efgh-ijkl"},
            {"type": "CVE", "value": "CVE-2024-1111"},
        ],
        "references": ["https://example.com/advisory"],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": "left-pad"},
                "vulnerable_version_range": "< 1.2.3",
                "patched_versions": "1.2.3",
            }
        ],
        "cvss": {
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "score": 9.8,
        },
    }
    payload.update(extra)
    return payload


def _osv(**extra):
    payload = {
        "id": "GHSA-abcd-efgh-ijkl",
        "summary": "Prototype pollution",
        "details": "Details",
        "aliases": ["CVE-2024-1111"],
        "modified": "2024-02-02T03:04:05Z",
        "published": "2024-01-02T03:04:05Z",
        "schema_version": "1.6.0",
        "references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "left-pad"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
                ],
                "versions": ["1.2.2"],
            }
        ],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    }
    payload.update(extra)
    return payload


def _nvd_cve(**cve_extra):
    cve = {
        "id": "CVE-2024-1111",
        "published": "2024-01-02T03:04:05.000",
        "lastModified": "2024-02-02T03:04:05.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Details"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                }
            ]
        },
        "references": [{"url": "https://example.com/advisory"}],
        "configurations": [
            {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*"}]}]}
        ],
    }
    cve.update(cve_extra)
    return {
        "vulnerabilities": [{"cve": cve}],
        "totalResults": 1,
        "startIndex": 0,
        "resultsPerPage": 1,
    }


def _history():
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "cveChanges": [
            {
                "change": {
                    "cveId": "CVE-2024-1111",
                    "eventName": "Initial Analysis",
                    "cveChangeId": "ABC",
                    "sourceIdentifier": "nvd@nist.gov",
                    "created": "2024-01-03T00:00:00.000",
                    "details": [{"action": "Added", "type": "CVSS V3.1"}],
                }
            }
        ],
    }


def _kev(**entry_extra):
    entry = {
        "cveID": "CVE-2024-1111",
        "vendorProject": "lodash",
        "product": "lodash",
        "vulnerabilityName": "Lodash prototype pollution",
        "dateAdded": "2024-01-02",
        "shortDescription": "Details",
        "requiredAction": "Apply updates",
        "dueDate": "2024-01-16",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "See https://example.com/kev",
    }
    entry.update(entry_extra)
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.10.26",
        "dateReleased": "2026-10-26T14:00:00Z",
        "count": 1,
        "vulnerabilities": [entry],
    }


def _call(kind, transport, **kwargs):
    budget = kwargs.pop("budget", WorkBudget())
    sleeps = kwargs.pop("sleeps", [])
    common = {
        "transport": transport,
        "budget": budget,
        "sleeper": pause(sleeps),
        "now": lambda: NOW,
    }
    if kind == "github":
        return fetch_github_advisories(advisory_types=("reviewed",), **common)
    if kind == "osv":
        return query_osv(package_name="left-pad", ecosystem="npm", version="1.0.0", **common)
    if kind == "nvd":
        return fetch_nvd_cve("CVE-2024-1111", include_changes=False, **common)
    return fetch_kev_catalog(**common)


@pytest.mark.parametrize("kind", ["github", "osv", "nvd", "cisa-kev"])
def test_valid_source_and_missing_optional_fields(kind):
    if kind == "github":
        payload = _ghsa()
        payload.pop("description")
        payload.pop("cvss")
        payload.pop("published_at")
        transport = ScriptTransport([response(200, [payload])])
    elif kind == "osv":
        payload = _osv()
        payload.pop("summary")
        payload.pop("severity")
        payload.pop("published")
        transport = ScriptTransport([response(200, {"vulns": [payload]})])
    elif kind == "nvd":
        payload = _nvd_cve()
        payload["vulnerabilities"][0]["cve"].pop("metrics")
        payload["vulnerabilities"][0]["cve"].pop("published")
        transport = ScriptTransport([response(200, payload)])
    else:
        payload = _kev()
        payload["vulnerabilities"][0].pop("notes")
        transport = ScriptTransport([response(200, payload)])
    batch = _call(kind, transport)
    record = batch.records[0]
    assert batch.complete is True
    assert record.published_at is None or kind == "cisa-kev"
    if kind == "github":
        assert record.summary is None
        assert record.severity == [] or all(item.score is None
            or item.system != "github" for item in record.severity)
    if kind == "nvd":
        assert record.affected == []
        assert record.known_exploited is None
        assert "lodash" not in [item.package_name for item in record.affected]
    dumped = batch.model_dump_json()
    assert SECRET not in dumped


def test_github_keeps_original_range_alias_and_does_not_fetch_references():
    sleeps = []
    transport = ScriptTransport([response(200, [_ghsa()]), response(200, [])])
    batch = fetch_github_advisories(
        advisory_types=("reviewed", "malware"),
        transport=transport,
        sleeper=pause(sleeps),
        now=lambda: NOW,
        github_token=SECRET,
    )
    reviewed = batch.records[0]
    assert reviewed.aliases == ["CVE-2024-1111"]
    assert reviewed.affected[0].ranges[0]["vulnerable_version_range"] == "< 1.2.3"
    assert reviewed.severity[0].score is None
    assert reviewed.severity[1].score == 9.8
    assert all("example.com" not in request.url for request in transport.requests)
    assert "type=malware" in transport.requests[1].url
    assert SECRET not in batch.model_dump_json()
    assert transport.requests[0].headers["Authorization"] == f"Bearer {SECRET}"


def test_github_malware_is_not_assumed_in_the_reviewed_list():
    payload = _ghsa(type="malware", cve_id=None, identifiers=[{"type": "GHSA",
        "value": "GHSA-abcd-efgh-ijkl"}])
    payload.pop("cvss")
    transport = ScriptTransport([response(200, [payload])])
    batch = fetch_github_advisories(
        advisory_types=("malware",),
        transport=transport,
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert batch.records[0].advisory_kind == "malware"
    assert batch.records[0].aliases == []
    assert "type=malware" in transport.requests[0].url


def test_same_payload_keeps_one_content_hash():
    transport = ScriptTransport([response(200, [_ghsa()])])
    first = fetch_github_advisories(
        advisory_types=("reviewed",),
        transport=transport,
        sleeper=pause([]),
        now=lambda: NOW,
    )
    transport.items.append(response(200, [_ghsa()]))
    second = fetch_github_advisories(
        advisory_types=("reviewed",),
        transport=transport,
        sleeper=pause([]),
        now=lambda: NOW + timedelta(days=1),
    )
    assert first.records[0].content_hash == second.records[0].content_hash
    assert first.records[0].retrieved_at != second.records[0].retrieved_at
    assert first.records[0].content_hash == content_hash(first.records[0].origin)


def test_github_pagination_and_budget_stop():
    first = response(
        200,
        [_ghsa()],
        {"Link": '<https://api.github.com/advisories?after=cursor-2&type=reviewed>; rel="next"'},
    )
    second_payload = _ghsa(ghsa_id="GHSA-zzzz-zzzz-zzzz", summary="Second")
    second_payload["identifiers"] = [{"type": "GHSA", "value": "GHSA-zzzz-zzzz-zzzz"}]
    full = ScriptTransport([first, response(200, [second_payload])])
    done = fetch_github_advisories(
        advisory_types=("reviewed",),
        transport=full,
        budget=WorkBudget(max_requests=2),
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert done.complete is True
    assert len(done.records) == 2
    limited = ScriptTransport(
        [
            response(
                200,
                [_ghsa()],
                {"Link": '<https://api.github.com/advisories?after=cursor-2>; rel="next"'},
            )
        ]
    )
    partial = fetch_github_advisories(
        advisory_types=("reviewed",),
        transport=limited,
        budget=WorkBudget(max_requests=1),
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert partial.complete is False
    assert len(partial.records) == 1
    assert "budget_exceeded" in partial.warnings
    assert partial.next_cursor is not None
    assert "cursor-2" in partial.next_cursor
    assert len(limited.requests) == 1


def test_repeated_cursor_stops():
    link = {"Link": '<https://api.github.com/advisories?after=same>; rel="next"'}
    transport = ScriptTransport(
        [
            response(200, [_ghsa()], link),
            response(200, [_ghsa()], link),
        ]
    )
    batch = fetch_github_advisories(
        advisory_types=("reviewed",),
        transport=transport,
        budget=WorkBudget(max_requests=4),
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert batch.complete is False
    assert "repeated_cursor" in batch.warnings
    assert len(transport.requests) == 2


@pytest.mark.parametrize(
    ("kind", "status", "body", "category"),
    [
        ("github", 401, {"token": SECRET, "detail": PRIVATE}, "unauthorized"),
        ("osv", 401, {"token": SECRET}, "unauthorized"),
        ("nvd", 401, {"token": SECRET}, "unauthorized"),
        ("cisa-kev", 403, {"detail": PRIVATE}, "forbidden"),
        ("github", 400, {"message": "bad"}, "unsupported"),
    ],
)
def test_auth_and_client_errors_hide_bodies(kind, status, body, category, caplog):
    caplog.set_level(0)
    transport = ScriptTransport([response(status, body)])
    with pytest.raises(SourceError) as caught:
        _call(kind, transport)
    assert caught.value.category == category
    text = str(caught.value)
    assert SECRET not in text
    assert PRIVATE not in text
    assert SECRET not in caplog.text
    assert PRIVATE not in caplog.text


def test_rate_limit_honors_short_retry_after_and_refuses_a_long_one():
    sleeps = []
    transport = ScriptTransport(
        [response(429, {"message": SECRET}, {"Retry-After": "1"}), response(200, [_ghsa()])]
    )
    batch = fetch_github_advisories(
        advisory_types=("reviewed",),
        transport=transport,
        budget=WorkBudget(max_retries=2, max_wait_seconds=2),
        sleeper=pause(sleeps),
        now=lambda: NOW,
    )
    assert batch.records
    assert sleeps == [1.0]
    assert SECRET not in str(batch)
    blocked = ScriptTransport([response(429, {"message": PRIVATE}, {"Retry-After": "30"})])
    with pytest.raises(SourceError) as caught:
        fetch_github_advisories(
            advisory_types=("reviewed",),
            transport=blocked,
            budget=WorkBudget(max_wait_seconds=2),
            sleeper=pause([]),
            now=lambda: NOW,
        )
    assert caught.value.category == "rate_limited"
    assert caught.value.retry_after_seconds == 30
    assert len(blocked.requests) == 1
    assert PRIVATE not in str(caught.value)


def test_github_403_rate_limit_is_not_a_normal_forbidden():
    transport = ScriptTransport(
        [response(403, {"message": "API rate limit exceeded"}, {"X-RateLimit-Remaining": "0"})]
    )
    with pytest.raises(SourceError) as caught:
        fetch_github_advisories(
            advisory_types=("reviewed",),
            transport=transport,
            budget=WorkBudget(max_retries=0),
            sleeper=pause([]),
            now=lambda: NOW,
        )
    assert caught.value.category == "rate_limited"


def test_server_error_retries_then_returns_the_record():
    sleeps = []
    transport = ScriptTransport([response(503, {"error": PRIVATE}), response(200,
        {"vulns": [_osv()]})])
    batch = query_osv(
        package_name="left-pad",
        ecosystem="npm",
        version="1.0.0",
        transport=transport,
        budget=WorkBudget(max_retries=2),
        sleeper=pause(sleeps),
        now=lambda: NOW,
    )
    assert batch.records[0].source_id == "GHSA-abcd-efgh-ijkl"
    assert sleeps
    assert PRIVATE not in batch.model_dump_json()


def test_timeout_invalid_json_and_unexpected_shape():
    with pytest.raises(SourceError) as timeout:
        query_osv(
            package_name="left-pad",
            ecosystem="npm",
            version="1.0.0",
        transport=ScriptTransport([TimeoutError()]),
        budget=WorkBudget(max_retries=0),
        sleeper=pause([]),
            now=lambda: NOW,
        )
    assert timeout.value.category == "timeout"
    with pytest.raises(SourceError) as invalid:
        fetch_kev_catalog(
            transport=ScriptTransport([response(200, b"not-json")]),
            sleeper=pause([]),
            now=lambda: NOW,
        )
    assert invalid.value.category == "invalid_response"
    assert invalid.value.reason == "invalid_json"
    with pytest.raises(SourceError) as shape:
        fetch_nvd_cve(
            "CVE-2024-1111",
            include_changes=False,
            transport=ScriptTransport([response(200, {"message": "nope"})]),
            sleeper=pause([]),
            now=lambda: NOW,
        )
    assert shape.value.reason == "unexpected_shape"


def test_later_page_failure_keeps_a_partial_batch():
    first = response(
        200,
        [_ghsa()],
        {"Link": '<https://api.github.com/advisories?after=next>; rel="next"'},
    )
    transport = ScriptTransport([first, response(500, {"error": PRIVATE})])
    batch = fetch_github_advisories(
        advisory_types=("reviewed",),
        transport=transport,
        budget=WorkBudget(max_retries=0),
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert len(batch.records) == 1
    assert batch.complete is False
    assert "http_500" in batch.warnings
    assert PRIVATE not in batch.model_dump_json()


def test_missing_advisory_is_not_an_authorization_failure():
    missing = fetch_github_advisory(
        "GHSA-abcd-efgh-ijkl",
        transport=ScriptTransport([response(404, {"message": "not found"})]),
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert missing.records == []
    assert "not_found" in missing.warnings
    with pytest.raises(SourceError) as denied:
        fetch_github_advisory(
            "GHSA-abcd-efgh-ijkl",
            transport=ScriptTransport([response(401, {"token": SECRET})]),
            github_token=SECRET,
            sleeper=pause([]),
            now=lambda: NOW,
        )
    assert denied.value.category == "unauthorized"
    assert SECRET not in str(denied.value)


def test_cursor_cannot_leave_the_public_advisory_api():
    evil = json.dumps(
        {
            "v": 1,
            "source": "github",
            "next_url": "https://evil.test/advisories",
            "queued_urls": [],
        }
    )
    transport = ScriptTransport([])
    with pytest.raises(SourceError) as caught:
        fetch_github_advisories(cursor=evil, transport=transport, sleeper=pause([]),
            now=lambda: NOW)
    assert caught.value.reason == "host_not_allowed"
    assert transport.requests == []
    leaked = json.dumps(
        {
            "v": 1,
            "source": "github",
            "next_url": f"https://api.github.com/advisories?apiKey={SECRET}",
            "queued_urls": [],
        }
    )
    with pytest.raises(SourceError) as secret_url:
        fetch_github_advisories(cursor=leaked, transport=transport, sleeper=pause([]),
            now=lambda: NOW)
    assert secret_url.value.reason == "secret_in_url"
    assert SECRET not in str(secret_url.value)


def test_osv_querybatch_ids_are_incomplete_until_detail_is_loaded():
    batch_payload = {"results": [{"vulns": [{"id": "GHSA-abcd-efgh-ijkl",
        "modified": "2024-02-02T03:04:05Z"}]}]}
    identifiers = query_osv_batch(
        [{"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.0.0"}],
        transport=ScriptTransport([response(200, batch_payload)]),
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert identifiers.records[0].warnings == ["detail_not_loaded"]
    assert identifiers.complete is True
    assert "identifiers_only" in identifiers.warnings
    resolved = query_osv_batch(
        [{"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.0.0"}],
        resolve_details=True,
        transport=ScriptTransport([response(200, batch_payload), response(200, _osv())]),
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert resolved.records[0].summary == "Details"
    assert "detail_not_loaded" not in resolved.records[0].warnings
    ranged = resolved.records[0].affected[0].ranges[0]
    assert ranged["type"] == "SEMVER"
    assert ranged["events"][1] == {"fixed": "1.2.3"}


def test_osv_page_token_stops_when_the_budget_is_spent():
    first = {"vulns": [_osv()], "next_page_token": "page-2"}
    transport = ScriptTransport([response(200, first)])
    batch = query_osv(
        package_name="left-pad",
        ecosystem="npm",
        version="1.0.0",
        transport=transport,
        budget=WorkBudget(max_requests=1),
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert batch.complete is False
    assert "page-2" in (batch.next_cursor or "")
    assert len(transport.requests) == 1
    assert "empty_result_is_not_absence_of_risk" in query_osv(
        package_name="left-pad",
        ecosystem="npm",
        version="9.9.9",
        transport=ScriptTransport([response(200, {"vulns": []})]),
        sleeper=pause([]),
        now=lambda: NOW,
    ).warnings


def test_nvd_does_not_invent_an_npm_package_and_keeps_original_severity():
    transport = ScriptTransport([response(200, _nvd_cve()), response(200, _history())])
    batch = fetch_nvd_cve(
        "CVE-2024-1111",
        nvd_api_key=SECRET,
        transport=transport,
        sleeper=pause([]),
        now=lambda: NOW,
    )
    record = batch.records[0]
    assert record.affected == []
    assert record.severity[0].system == "CVSS_V3.1"
    assert record.severity[0].score == 9.8
    assert record.severity[0].value.startswith("CVSS:3.1/")
    assert record.changes[0]["change"]["eventName"] == "Initial Analysis"
    assert record.content_hash == content_hash(record.origin)
    assert "cveChanges" not in record.origin
    assert SECRET not in batch.model_dump_json()
    assert transport.requests[0].headers["apiKey"] == SECRET
    assert "apiKey" not in transport.requests[0].url
    assert "nvd_product_data_is_not_an_npm_identity" in record.warnings


def test_nvd_incomplete_record_and_window_budget():
    waiting = _nvd_cve(vulnStatus="Awaiting Analysis")
    waiting["vulnerabilities"][0]["cve"].pop("metrics")
    waiting["vulnerabilities"][0]["cve"].pop("descriptions")
    batch = fetch_nvd_cve(
        "CVE-2024-1111",
        include_changes=False,
        transport=ScriptTransport([response(200, waiting)]),
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert "nvd_analysis_incomplete" in batch.records[0].warnings
    assert "severity_not_provided" in batch.records[0].warnings
    assert batch.records[0].known_exploited is None
    start = datetime(2024, 1, 1, tzinfo=UTC)
    partial = fetch_nvd_modified(
        modified_since=start,
        modified_until=datetime(2025, 1, 1, tzinfo=UTC),
        transport=ScriptTransport([response(200, _nvd_cve())]),
        budget=WorkBudget(max_requests=1),
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert partial.complete is False
    assert "nvd_window_capped_120_days" in partial.warnings
    assert partial.next_cursor is not None
    assert "2025-01-01" in partial.next_cursor


def test_kev_signal_lookup_and_unchanged_catalog():
    transport = ScriptTransport([response(200, _kev())])
    catalog = fetch_kev_catalog(transport=transport, sleeper=pause([]), now=lambda: NOW)
    record = catalog.records[0]
    assert record.affected == []
    assert record.known_exploited is not None
    assert record.known_exploited.known is True
    assert record.known_exploited.ransomware_use == "Unknown"
    assert record.origin["product"] == "lodash"
    assert "https://example.com/kev" in record.references
    assert all(request.url.startswith("https://www.cisa.gov/") for request in transport.requests)
    hit = lookup_kev(catalog, "cve-2024-1111")
    assert hit.found is True
    miss = lookup_kev(catalog, "CVE-2024-9999")
    assert miss.found is False
    assert miss.known_exploited is None
    again = fetch_kev_catalog(
        cursor=catalog.next_cursor,
        transport=ScriptTransport([response(200, _kev())]),
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert again.records == []
    assert "catalog_unchanged" in again.warnings
    assert again.complete is True


def test_kev_count_mismatch_is_incomplete():
    payload = _kev()
    payload["count"] = 5
    batch = fetch_kev_catalog(
        transport=ScriptTransport([response(200, payload)]),
        sleeper=pause([]),
        now=lambda: NOW,
    )
    assert batch.complete is False
    assert "catalog_count_mismatch" in batch.warnings
