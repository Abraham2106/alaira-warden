"""NVD CVE API 2.0 and CVE Change History.

Documentation consulted on 2026-10-26:
https://nvd.nist.gov/developers/start-here
https://nvd.nist.gov/developers/vulnerabilities

The API key is sent only in the ``apiKey`` header, never in the URL. Public limit:
5 requests per rolling 30 seconds. With a key: 50 requests per rolling 30 seconds.
Date windows cannot exceed 120 consecutive days; this client caps a window at 119
days and returns a cursor for the remainder. NIST asks products to display:
"This product uses data from the NVD API but is not endorsed or certified by the NVD."

CPE configurations and the vendor/product ``affected`` array are kept in ``origin``.
They are not converted into npm package names. Missing CVSS stays an empty severity
list. ``cisaExploitAdd`` is an exploitation signal from the NVD document; its absence
does not set ``known_exploited`` to false.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from alaira_warden.intelligence.errors import SourceError
from alaira_warden.intelligence.hashing import content_hash
from alaira_warden.intelligence.http import (
    USER_AGENT,
    Transport,
    UrllibTransport,
    WorkBudget,
    request_json,
)
from alaira_warden.intelligence.models import (
    Attribution,
    KnownExploited,
    Severity,
    SourceBatch,
    SourceRecord,
)
from alaira_warden.intelligence.textutil import (
    CVE_RE,
    canonical_identifier,
    dedupe,
    dump_cursor,
    load_cursor,
    nvd_timestamp,
    parse_timestamp,
    reference_list,
    require_aware,
)

NVD_HOSTS = frozenset({"services.nvd.nist.gov"})
CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HISTORY_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
DOCS = "https://nvd.nist.gov/developers/vulnerabilities"
NIST_NOTICE = "This product uses data from the NVD API but is not endorsed or certified by the NVD."
_WINDOW = timedelta(days=119)
_INCOMPLETE = {"awaiting analysis", "received", "undergoing analysis", "deferred"}
_ATTRIBUTION = Attribution(
    provider="NVD",
    documentation_url=DOCS,
    notes=NIST_NOTICE + " NIST publications are in the public domain under 17 USC.",
)


def _path_allowed(path: str) -> bool:
    trimmed = path.rstrip("/") or "/"
    return trimmed in {"/rest/json/cves/2.0", "/rest/json/cvehistory/2.0"}


def _headers(api_key: str | None) -> dict[str, str]:
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if api_key and api_key.strip():
        headers["apiKey"] = api_key.strip()
    return headers


def normalize_nvd_cve(
    vulnerability: Mapping[str, Any], *, retrieved_at: datetime
) -> tuple[SourceRecord | None, str | None]:
    cve = vulnerability.get("cve") if isinstance(vulnerability.get("cve"), dict) else vulnerability
    if not isinstance(cve, dict):
        return None, "skipped_incomplete_entry"
    identifier = canonical_identifier(cve.get("id"))
    if identifier is None or not CVE_RE.fullmatch(identifier):
        return None, "skipped_incomplete_entry"
    warnings = ["nvd_configurations_not_mapped_to_npm"]
    if cve.get("configurations") or cve.get("affected"):
        warnings.append("nvd_product_data_is_not_an_npm_identity")
    status = cve.get("vulnStatus") if isinstance(cve.get("vulnStatus"), str) else None
    if status and status.casefold() in _INCOMPLETE:
        warnings.append("nvd_analysis_incomplete")
    summary = _english_description(cve.get("descriptions"))
    if summary is None:
        warnings.append("description_not_provided")
    severity = _severities(cve.get("metrics"))
    if not severity:
        warnings.append("severity_not_provided")
    published = parse_timestamp(cve.get("published"))
    modified = parse_timestamp(cve.get("lastModified"))
    if cve.get("published") and published is None:
        warnings.append("unparsed_timestamp")
    known = None
    if cve.get("cisaExploitAdd"):
        known = KnownExploited(
            known=True,
            source="nvd",
            date_added=parse_timestamp(cve.get("cisaExploitAdd")),
            detail="cisaExploitAdd is present on the NVD CVE record; KEV was not queried.",
        )
    origin = dict(vulnerability)
    record = SourceRecord(
        source="nvd",
        source_id=identifier,
        aliases=[],
        title=identifier,
        summary=summary,
        source_url=f"https://nvd.nist.gov/vuln/detail/{identifier}",
        published_at=published,
        modified_at=modified,
        retrieved_at=retrieved_at,
        content_hash=content_hash(origin),
        references=reference_list(cve.get("references")),
        affected=[],
        severity=severity,
        known_exploited=known,
        license="Public domain (17 USC)",
        attribution=_ATTRIBUTION,
        origin=origin,
        warnings=dedupe(warnings),
        source_status=status,
    )
    return record, None


def fetch_nvd_cve(
    cve_id: str,
    *,
    include_changes: bool = True,
    history_start: int = 0,
    nvd_api_key: str | None = None,
    transport: Transport | None = None,
    budget: WorkBudget | None = None,
    sleeper: Callable[[float], None] | None = None,
    now: Callable[[], datetime] | None = None,
) -> SourceBatch:
    """Fetch one CVE. Change history is attached when ``include_changes`` is true.

    History is not part of the content hash. A history failure keeps the CVE record
    and marks the batch incomplete.
    """

    identifier = canonical_identifier(cve_id)
    if identifier is None or not CVE_RE.fullmatch(identifier):
        raise SourceError(
            category="unsupported", source="nvd", operation="get_cve", reason="invalid_cve_id"
        )
    clock = now or (lambda: datetime.now(UTC))
    retrieved_at = clock()
    worker = transport or UrllibTransport()
    limits = budget or WorkBudget()
    pause = sleeper or time.sleep
    records, complete, warnings, _cursor = _collect_cves(
        {"cveId": identifier},
        retrieved_at=retrieved_at,
        transport=worker,
        budget=limits,
        sleeper=pause,
        clock=clock,
        api_key=nvd_api_key,
    )
    if not records:
        return _batch(retrieved_at, [], True, None, ["not_found",
            "empty_result_is_not_absence_of_risk"])
    if not include_changes:
        return _batch(retrieved_at, records, complete, None, warnings)
    if limits.remaining_requests() <= 0 or limits.expired():
        warnings.append("budget_exceeded")
        warnings.append("change_history_not_loaded")
        return _batch(retrieved_at, records, False, _history_cursor(identifier, 0), warnings)
    changes, history_complete, history_warnings, history_cursor = _collect_changes(
        identifier,
        start_index=history_start,
        retrieved_at=retrieved_at,
        transport=worker,
        budget=limits,
        sleeper=pause,
        clock=clock,
        api_key=nvd_api_key,
    )
    records[0] = records[0].model_copy(update={"changes": changes})
    warnings.extend(history_warnings)
    return _batch(retrieved_at, records, complete and history_complete, history_cursor,
        dedupe(warnings))


def fetch_nvd_modified(
    *,
    modified_since: datetime,
    modified_until: datetime | None = None,
    cursor: str | None = None,
    results_per_page: int = 100,
    nvd_api_key: str | None = None,
    transport: Transport | None = None,
    budget: WorkBudget | None = None,
    sleeper: Callable[[float], None] | None = None,
    now: Callable[[], datetime] | None = None,
) -> SourceBatch:
    """CVEs modified in a window. Windows longer than 119 days are split via the cursor."""

    clock = now or (lambda: datetime.now(UTC))
    retrieved_at = clock()
    if cursor:
        state = load_cursor(cursor, source="nvd", operation="list_cves")
        params = state.get("params")
        if not isinstance(params, dict) or not all(isinstance(value,
            str) for value in params.values()):
            raise SourceError(
                category="unsupported", source="nvd", operation="list_cves", reason="invalid_cursor"
            )
        query = {str(key): str(value) for key, value in params.items()}
    else:
        start = require_aware(modified_since, source="nvd", operation="list_cves")
        end = require_aware(modified_until or clock(), source="nvd", operation="list_cves")
        if end < start:
            raise SourceError(
                category="unsupported", source="nvd", operation="list_cves",
                    reason="invalid_date_window"
            )
        window_end = min(end, start + _WINDOW)
        query = {
            "lastModStartDate": nvd_timestamp(start),
            "lastModEndDate": nvd_timestamp(window_end),
            "startIndex": "0",
            "resultsPerPage": str(min(2000, max(1, results_per_page))),
        }
        if window_end < end:
            query["pendingWindowStart"] = nvd_timestamp(window_end)
            query["pendingWindowEnd"] = nvd_timestamp(end)
    records, complete, warnings, next_params = _collect_cves(
        query,
        retrieved_at=retrieved_at,
        transport=transport or UrllibTransport(),
        budget=budget or WorkBudget(),
        sleeper=sleeper or time.sleep,
        clock=clock,
        api_key=nvd_api_key,
    )
    cursor_text = None
    if next_params:
        complete = False
        cursor_text = dump_cursor({"v": 1, "source": "nvd", "operation": "list_cves",
            "params": next_params})
    if not records and complete:
        warnings.append("empty_result_is_not_absence_of_risk")
    return _batch(retrieved_at, records, complete, cursor_text, dedupe(warnings))


def _collect_cves(
    params: Mapping[str, str],
    *,
    retrieved_at: datetime,
    transport: Transport,
    budget: WorkBudget,
    sleeper: Callable[[float], None],
    clock: Callable[[], datetime],
    api_key: str | None,
) -> tuple[list[SourceRecord], bool, list[str], dict[str, str] | None]:
    records: list[SourceRecord] = []
    warnings: list[str] = []
    current = {key: value for key, value in params.items() if key not in {"pendingWindowStart",
        "pendingWindowEnd"}}
    pending_start = params.get("pendingWindowStart")
    pending_end = params.get("pendingWindowEnd")
    if pending_start:
        warnings.append("nvd_window_capped_120_days")
    seen: set[str] = set()
    while True:
        marker = urlencode(sorted(current.items()))
        if marker in seen:
            warnings.append("repeated_cursor")
            return records, False, warnings, _carry(current, pending_start, pending_end)
        if budget.remaining_requests() <= 0 or budget.expired():
            warnings.append("budget_exceeded")
            return records, False, warnings, _carry(current, pending_start, pending_end)
        seen.add(marker)
        try:
            result = request_json(
                source="nvd",
                operation="list_cves",
                method="GET",
                url=CVE_URL + "?" + urlencode(current),
                headers=_headers(api_key),
                body=None,
                transport=transport,
                budget=budget,
                sleeper=sleeper,
                hosts=NVD_HOSTS,
                path_allowed=_path_allowed,
                now=clock,
            )
        except SourceError as error:
            if records:
                warnings.append(error.warning_code)
                return records, False, warnings, _carry(current, pending_start, pending_end)
            raise
        if result.status_code == 404:
            warnings.append("not_found")
            return records, True, warnings, None
        payload = result.payload
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise SourceError(
                category="invalid_response", source="nvd", operation="list_cves",
                    reason="unexpected_shape"
            )
        for item in payload["vulnerabilities"]:
            if not isinstance(item, dict):
                warnings.append("skipped_incomplete_entry")
                continue
            record, warning = normalize_nvd_cve(item, retrieved_at=retrieved_at)
            if warning:
                warnings.append(warning)
            if record is not None:
                records.append(record)
                warnings.extend(record.warnings)
        total = payload.get("totalResults")
        start = payload.get("startIndex") if isinstance(payload.get("startIndex"),
            int) else int(current.get("startIndex", "0"))
        count = len(payload["vulnerabilities"])
        if isinstance(total, int) and start + count < total:
            if not count:
                warnings.append("empty_page_before_total")
                return records, False, warnings, _carry(current, pending_start, pending_end)
            current = dict(current)
            current["startIndex"] = str(start + count)
            continue
        if not isinstance(total, int):
            warnings.append("total_unknown")
            page = int(current.get("resultsPerPage", "0") or "0")
            if page and count >= page:
                return records, False, warnings, _carry(current, pending_start, pending_end)
        if pending_start and pending_end:
            start_at = parse_timestamp(pending_start)
            end_at = parse_timestamp(pending_end)
            page_size = current.get("resultsPerPage", "100")
            if start_at is not None and end_at is not None and end_at > start_at + _WINDOW:
                window_end = start_at + _WINDOW
                current = {
                    "lastModStartDate": nvd_timestamp(start_at),
                    "lastModEndDate": nvd_timestamp(window_end),
                    "startIndex": "0",
                    "resultsPerPage": page_size,
                }
                pending_start = nvd_timestamp(window_end)
                pending_end = nvd_timestamp(end_at)
                warnings.append("nvd_window_capped_120_days")
                continue
            current = {
                "lastModStartDate": pending_start,
                "lastModEndDate": pending_end,
                "startIndex": "0",
                "resultsPerPage": page_size,
            }
            pending_start = None
            pending_end = None
            continue
        return records, True, warnings, None


def _collect_changes(
    cve_id: str,
    *,
    start_index: int,
    retrieved_at: datetime,
    transport: Transport,
    budget: WorkBudget,
    sleeper: Callable[[float], None],
    clock: Callable[[], datetime],
    api_key: str | None,
) -> tuple[list[dict[str, Any]], bool, list[str], str | None]:
    del retrieved_at
    changes: list[dict[str, Any]] = []
    warnings: list[str] = []
    index = start_index
    seen: set[int] = set()
    while True:
        if index in seen:
            warnings.append("repeated_cursor")
            return changes, False, warnings, _history_cursor(cve_id, index)
        if budget.remaining_requests() <= 0 or budget.expired():
            warnings.append("budget_exceeded")
            warnings.append("change_history_not_loaded")
            return changes, False, warnings, _history_cursor(cve_id, index)
        seen.add(index)
        params = {"cveIds": cve_id, "startIndex": str(index), "resultsPerPage": "100"}
        try:
            result = request_json(
                source="nvd",
                operation="cve_history",
                method="GET",
                url=HISTORY_URL + "?" + urlencode(params),
                headers=_headers(api_key),
                body=None,
                transport=transport,
                budget=budget,
                sleeper=sleeper,
                hosts=NVD_HOSTS,
                path_allowed=_path_allowed,
                now=clock,
            )
        except SourceError as error:
            warnings.append(error.warning_code)
            warnings.append("change_history_unavailable")
            return changes, False, warnings, _history_cursor(cve_id, index)
        if result.status_code == 404 or result.payload is None:
            warnings.append("change_history_not_found")
            return changes, True, warnings, None
        payload = result.payload
        if not isinstance(payload, dict) or not isinstance(payload.get("cveChanges"), list):
            warnings.append("change_history_unexpected")
            return changes, False, warnings, _history_cursor(cve_id, index)
        for item in payload["cveChanges"]:
            if isinstance(item, dict):
                changes.append(dict(item))
            else:
                warnings.append("skipped_incomplete_entry")
        total = payload.get("totalResults")
        count = len(payload["cveChanges"])
        if isinstance(total, int) and index + count < total and count:
            index = index + count
            continue
        return changes, True, warnings, None


def _carry(
    current: dict[str, str], pending_start: str | None, pending_end: str | None
) -> dict[str, str]:
    merged = dict(current)
    if pending_start:
        merged["pendingWindowStart"] = pending_start
    if pending_end:
        merged["pendingWindowEnd"] = pending_end
    return merged


def _history_cursor(cve_id: str, start_index: int) -> str:
    return dump_cursor(
        {
            "v": 1,
            "source": "nvd",
            "operation": "cve_history",
            "cve_id": cve_id,
            "start_index": start_index,
        }
    )


def _english_description(value: object) -> str | None:
    if not isinstance(value, list):
        return None
    fallback = None
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("value"), str):
            continue
        if item.get("lang") == "en":
            return item["value"]
        if fallback is None:
            fallback = item["value"]
    return fallback


def _severities(metrics: object) -> list[Severity]:
    if not isinstance(metrics, dict):
        return []
    found: list[Severity] = []
    for values in metrics.values():
        if not isinstance(values, list):
            continue
        for metric in values:
            if not isinstance(metric, dict):
                continue
            data = metric.get("cvssData") if isinstance(metric.get("cvssData"), dict) else {}
            vector = data.get("vectorString") if isinstance(data, dict) else None
            version = data.get("version") if isinstance(data, dict) else None
            score = data.get("baseScore") if isinstance(data, dict) else None
            numeric = float(score) if isinstance(score, int | float) and not isinstance(score,
                bool) else None
            found.append(
                Severity(
                    system=f"CVSS_V{version}" if isinstance(version, str) else None,
                    value=vector if isinstance(vector, str) else None,
                    score=numeric,
                    source=metric.get("source") if isinstance(metric.get("source"), str) else None,
                    raw=dict(metric),
                )
            )
    return found


def _batch(
    retrieved_at: datetime,
    records: list[SourceRecord],
    complete: bool,
    cursor: str | None,
    warnings: list[str],
) -> SourceBatch:
    return SourceBatch(
        source="nvd",
        retrieved_at=retrieved_at,
        records=records,
        complete=complete,
        next_cursor=cursor,
        warnings=dedupe(warnings),
    )
