"""GitHub Advisory Database, public global advisories only.

Documentation consulted on 2026-10-26:
https://docs.github.com/en/rest/security-advisories/global-advisories
API version header ``2022-11-28``. A list with no ``type`` returns reviewed
advisories and excludes malware. Malware requires ``type=malware``. This client
does not call repository, private-advisory, or write endpoints.

Pagination follows the HTTPS ``Link`` ``rel=next`` URL on ``api.github.com`` and
only the ``/advisories`` paths. Rate limits documented the same day at
https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api :
60 requests/hour unauthenticated, 5,000/hour for a personal token. Secondary
limits can still return 403 or 429. A long ``Retry-After`` is reported and not
slept inside the call.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

from alaira_warden.intelligence.errors import SourceError
from alaira_warden.intelligence.hashing import content_hash
from alaira_warden.intelligence.http import (
    USER_AGENT,
    JsonResult,
    Transport,
    UrllibTransport,
    WorkBudget,
    link_next,
    request_json,
)
from alaira_warden.intelligence.models import (
    AffectedEntry,
    Attribution,
    Severity,
    SourceBatch,
    SourceRecord,
)
from alaira_warden.intelligence.textutil import (
    canonical_identifier,
    clean_reference,
    dedupe,
    dump_cursor,
    load_cursor,
    parse_timestamp,
    reference_list,
    require_aware,
)

GITHUB_HOSTS = frozenset({"api.github.com"})
DOCS = "https://docs.github.com/en/rest/security-advisories/global-advisories"
ADVISORY_TYPES = frozenset({"reviewed", "malware", "unreviewed"})
_ATTRIBUTION = Attribution(
    provider="GitHub Advisory Database",
    documentation_url=DOCS,
    notes=(
        "Public global advisories via the REST API. A token is optional and is not "
        "required for public reads. This client does not read private repositories "
        "or publish pull requests. Malware advisories are omitted unless type=malware."
    ),
)


def _path_allowed(path: str) -> bool:
    trimmed = path.rstrip("/") or "/"
    if trimmed == "/advisories":
        return True
    prefix, _, identifier = trimmed.rpartition("/")
    canonical = canonical_identifier(identifier)
    return prefix == "/advisories" and canonical is not None and canonical.startswith("GHSA-")


def _headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    if token and token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    return headers


def _cvss_system(vector: str) -> str:
    if vector.startswith("CVSS:3.1/"):
        return "CVSS_V3.1"
    if vector.startswith("CVSS:3.0/"):
        return "CVSS_V3.0"
    if vector.startswith("CVSS:4.0/"):
        return "CVSS_V4.0"
    return "CVSS"


def _optional_score(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def normalize_github_advisory(
    payload: Mapping[str, Any], *, retrieved_at: datetime
) -> tuple[SourceRecord | None, str | None]:
    identifier = canonical_identifier(payload.get("ghsa_id"))
    if identifier is None or not identifier.startswith("GHSA-"):
        return None, "skipped_incomplete_entry"
    aliases: list[str] = []
    for item in payload.get("identifiers") or []:
        if isinstance(item, dict):
            found = canonical_identifier(item.get("value"))
            if found and found != identifier:
                aliases.append(found)
    cve = canonical_identifier(payload.get("cve_id"))
    if cve and cve not in aliases and cve != identifier:
        aliases.append(cve)
    warnings: list[str] = []
    affected: list[AffectedEntry] = []
    vulnerabilities = payload.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        warnings.append("unexpected_affected_shape")
        vulnerabilities = []
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            warnings.append("skipped_incomplete_entry")
            continue
        package = entry.get("package") if isinstance(entry.get("package"), dict) else {}
        name = package.get("name") if isinstance(package, dict) else None
        ecosystem = package.get("ecosystem") if isinstance(package, dict) else None
        if not isinstance(name, str) or not name.strip():
            warnings.append("affected_package_name_missing")
            continue
        ranges: list[Any] = []
        has_range = entry.get("vulnerable_version_range") is not None
        has_patched = entry.get("patched_versions") is not None
        if has_range or has_patched:
            ranges.append(
                {
                    "type": "github_vulnerable_version_range",
                    "vulnerable_version_range": entry.get("vulnerable_version_range"),
                    "patched_versions": entry.get("patched_versions"),
                }
            )
        affected.append(
            AffectedEntry(
                ecosystem=ecosystem if isinstance(ecosystem, str) else None,
                package_name=name.strip(),
                ranges=ranges,
                versions=None,
            )
        )
    severity: list[Severity] = []
    label = payload.get("severity")
    if isinstance(label, str) and label:
        severity.append(
            Severity(system="github", value=label, score=None, source="github",
                raw={"severity": label})
        )
    cvss = payload.get("cvss")
    if isinstance(cvss, dict) and isinstance(cvss.get("vector_string"), str):
        severity.append(
            Severity(
                system=_cvss_system(cvss["vector_string"]),
                value=cvss["vector_string"],
                score=_optional_score(cvss.get("score")),
                source="github",
                raw=dict(cvss),
            )
        )
    html_url = clean_reference(payload.get("html_url"))
    source_url = html_url or f"https://github.com/advisories/{identifier}"
    withdrawn = parse_timestamp(payload.get("withdrawn_at"))
    kind = payload.get("type") if isinstance(payload.get("type"), str) else None
    published = parse_timestamp(payload.get("published_at"))
    modified = parse_timestamp(payload.get("updated_at"))
    if payload.get("published_at") and published is None:
        warnings.append("unparsed_timestamp")
    if payload.get("updated_at") and modified is None:
        warnings.append("unparsed_timestamp")
    origin = dict(payload)
    summary = payload.get("description") if isinstance(payload.get("description"), str) else None
    title = payload.get("summary") if isinstance(payload.get("summary"), str) else None
    return (
        SourceRecord(
            source="github",
            source_id=identifier,
            aliases=dedupe(aliases),
            title=title,
            summary=summary,
            source_url=source_url,
            published_at=published,
            modified_at=modified,
            retrieved_at=retrieved_at,
            content_hash=content_hash(origin),
            references=reference_list(payload.get("references")),
            affected=affected,
            severity=severity,
            known_exploited=None,
            license=None,
            attribution=_ATTRIBUTION,
            origin=origin,
            warnings=warnings,
            advisory_kind=kind,
            source_status="withdrawn" if withdrawn is not None else kind,
        ),
        None,
    )


def _list_url(
    *,
    ecosystem: str | None,
    advisory_type: str,
    per_page: int,
    updated_since: datetime | None,
    ghsa_id: str | None,
    cve_id: str | None,
) -> str:
    params: dict[str, str] = {
        "type": advisory_type,
        "per_page": str(per_page),
        "sort": "updated",
        "direction": "asc",
    }
    if ecosystem:
        params["ecosystem"] = ecosystem
    if updated_since is not None:
        params["updated"] = ">=" + updated_since.strftime("%Y-%m-%dT%H:%M:%SZ")
    if ghsa_id:
        params["ghsa_id"] = ghsa_id
    if cve_id:
        params["cve_id"] = cve_id
    return "https://api.github.com/advisories?" + urlencode(params)


def _cursor_state(cursor: str) -> tuple[str, list[str]]:
    payload = load_cursor(cursor, source="github", operation="list_advisories")
    current = payload.get("next_url")
    queued = payload.get("queued_urls") or []
    queued_ok = isinstance(queued, list) and all(isinstance(item, str) for item in queued)
    if not isinstance(current, str) or not queued_ok:
        raise SourceError(
            category="unsupported",
            source="github",
            operation="list_advisories",
            reason="invalid_cursor",
        )
    return current, list(queued)


def _encode_cursor(current: str, queued: list[str]) -> str:
    return dump_cursor({"v": 1, "source": "github", "next_url": current, "queued_urls": queued})


def fetch_github_advisories(
    *,
    ecosystem: str | None = "npm",
    advisory_types: tuple[str, ...] = ("reviewed", "malware"),
    updated_since: datetime | None = None,
    ghsa_id: str | None = None,
    cve_id: str | None = None,
    per_page: int = 100,
    cursor: str | None = None,
    github_token: str | None = None,
    transport: Transport | None = None,
    budget: WorkBudget | None = None,
    sleeper: Callable[[float], None] | None = None,
    now: Callable[[], datetime] | None = None,
) -> SourceBatch:
    """List public advisories. Reviewed and malware are separate requests.

    An empty page is a successful empty result, not proof that a package is safe.
    ``next_cursor`` continues the current page URL and any advisory types not started.
    """

    clock = now or (lambda: datetime.now(UTC))
    retrieved_at = clock()
    if updated_since is not None:
        updated_since = require_aware(updated_since, source="github", operation="list_advisories")
    page_size = min(100, max(1, per_page))
    if cursor:
        current, queued = _cursor_state(cursor)
    else:
        if not advisory_types:
            raise SourceError(
                category="unsupported",
                source="github",
                operation="list_advisories",
                reason="advisory_type_required",
            )
        unknown = [item for item in advisory_types if item not in ADVISORY_TYPES]
        if unknown:
            raise SourceError(
                category="unsupported",
                source="github",
                operation="list_advisories",
                reason="advisory_type_unsupported",
            )
        urls = [
            _list_url(
                ecosystem=ecosystem,
                advisory_type=item,
                per_page=page_size,
                updated_since=updated_since,
                ghsa_id=ghsa_id,
                cve_id=cve_id,
            )
            for item in advisory_types
        ]
        current, queued = urls[0], urls[1:]
    worker = transport or UrllibTransport()
    limits = budget or WorkBudget()
    pause = sleeper or time.sleep
    records: list[SourceRecord] = []
    warnings: list[str] = []
    seen: set[str] = set()
    while True:
        if current in seen:
            warnings.append("repeated_cursor")
            return _batch(retrieved_at, records, False, _encode_cursor(current, queued), warnings)
        if limits.remaining_requests() <= 0 or limits.expired():
            warnings.append("budget_exceeded")
            return _batch(retrieved_at, records, False, _encode_cursor(current, queued), warnings)
        seen.add(current)
        try:
            result = request_json(
                source="github",
                operation="list_advisories",
                method="GET",
                url=current,
                headers=_headers(github_token),
                body=None,
                transport=worker,
                budget=limits,
                sleeper=pause,
                hosts=GITHUB_HOSTS,
                path_allowed=_path_allowed,
                now=clock,
            )
        except SourceError as error:
            if records:
                warnings.append(error.warning_code)
                return _batch(
                    retrieved_at, records, False, _encode_cursor(current, queued), warnings
                )
            raise
        try:
            page, page_warnings = _page_records(result, retrieved_at=retrieved_at)
        except SourceError as error:
            if records:
                warnings.append(error.warning_code)
                return _batch(
                    retrieved_at, records, False, _encode_cursor(current, queued), warnings
                )
            raise
        records.extend(page)
        warnings.extend(page_warnings)
        nxt = None if result.status_code == 404 else link_next(result.headers)
        if result.status_code == 404:
            warnings.append("not_found")
        if nxt:
            current = nxt
            continue
        if queued:
            current = queued.pop(0)
            continue
        if not records:
            warnings.append("empty_result_is_not_absence_of_risk")
        return _batch(retrieved_at, records, True, None, dedupe(warnings))


def fetch_github_advisory(
    ghsa_id: str,
    *,
    github_token: str | None = None,
    transport: Transport | None = None,
    budget: WorkBudget | None = None,
    sleeper: Callable[[float], None] | None = None,
    now: Callable[[], datetime] | None = None,
) -> SourceBatch:
    """Fetch one public advisory by GHSA id. 404 is an empty batch, not a denial."""

    identifier = canonical_identifier(ghsa_id)
    if identifier is None or not identifier.startswith("GHSA-"):
        raise SourceError(
            category="unsupported",
            source="github",
            operation="get_advisory",
            reason="invalid_ghsa_id",
        )
    clock = now or (lambda: datetime.now(UTC))
    retrieved_at = clock()
    result = request_json(
        source="github",
        operation="get_advisory",
        method="GET",
        url=f"https://api.github.com/advisories/{identifier}",
        headers=_headers(github_token),
        body=None,
        transport=transport or UrllibTransport(),
        budget=budget or WorkBudget(),
        sleeper=sleeper or time.sleep,
        hosts=GITHUB_HOSTS,
        path_allowed=_path_allowed,
        now=clock,
    )
    if result.status_code == 404 or result.payload is None:
        return _batch(
            retrieved_at,
            [],
            True,
            None,
            ["not_found", "empty_result_is_not_absence_of_risk"],
        )
    if not isinstance(result.payload, dict):
        raise SourceError(
            category="invalid_response",
            source="github",
            operation="get_advisory",
            reason="unexpected_shape",
        )
    record, _warning = normalize_github_advisory(result.payload, retrieved_at=retrieved_at)
    if record is None:
        raise SourceError(
            category="invalid_response",
            source="github",
            operation="get_advisory",
            reason="unexpected_shape",
        )
    return _batch(retrieved_at, [record], True, None, dedupe(record.warnings))


def _page_records(
    result: JsonResult, *, retrieved_at: datetime
) -> tuple[list[SourceRecord], list[str]]:
    if result.status_code == 404:
        return [], []
    if not isinstance(result.payload, list):
        raise SourceError(
            category="invalid_response",
            source="github",
            operation="list_advisories",
            reason="unexpected_shape",
        )
    records: list[SourceRecord] = []
    warnings: list[str] = []
    for item in result.payload:
        if not isinstance(item, dict):
            warnings.append("skipped_incomplete_entry")
            continue
        record, warning = normalize_github_advisory(item, retrieved_at=retrieved_at)
        if warning:
            warnings.append(warning)
        if record is not None:
            records.append(record)
            warnings.extend(record.warnings)
    return records, warnings


def _batch(
    retrieved_at: datetime,
    records: list[SourceRecord],
    complete: bool,
    cursor: str | None,
    warnings: list[str],
) -> SourceBatch:
    return SourceBatch(
        source="github",
        retrieved_at=retrieved_at,
        records=records,
        complete=complete,
        next_cursor=cursor,
        warnings=dedupe(warnings),
    )
