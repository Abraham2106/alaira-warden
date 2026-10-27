"""OSV.dev v1 query, querybatch, and vulnerability detail.

Documentation consulted on 2026-10-26:
https://google.github.io/osv.dev/api/
https://google.github.io/osv.dev/post-v1-query/
https://google.github.io/osv.dev/post-v1-querybatch/
https://google.github.io/osv.dev/faq/

The FAQ states the API is not rate limited and that HTTP/1.1 responses are capped
at 32MiB. ``/v1/query`` paginates with ``next_page_token`` above roughly 1,000
vulnerabilities. ``/v1/querybatch`` returns ids and ``modified`` only; detail is a
separate ``GET /v1/vulns/{id}``. Withdrawn records are excluded from query results
and remain available by id. There is no modified-since cursor on these endpoints;
the bulk ``modified_id.csv`` export is intentionally not downloaded here.
An empty ``vulns`` list does not mean the inventory is complete or risk-free.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from alaira_warden.intelligence.errors import SourceError
from alaira_warden.intelligence.hashing import content_hash
from alaira_warden.intelligence.http import Transport, UrllibTransport, WorkBudget, request_json
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
)

OSV_HOSTS = frozenset({"api.osv.dev"})
DOCS = "https://google.github.io/osv.dev/api/"
_ATTRIBUTION = Attribution(
    provider="OSV.dev",
    documentation_url=DOCS,
    notes=(
        "OSV aggregates records from upstream databases. The FAQ consulted on "
        "2026-10-26 does not attach a per-record SPDX license; license stays null "
        "unless the payload itself carries one. Querybatch rows are not full records."
    ),
)


def _path_allowed(path: str) -> bool:
    trimmed = path.rstrip("/") or "/"
    if trimmed in {"/v1/query", "/v1/querybatch"}:
        return True
    prefix, _, identifier = trimmed.rpartition("/")
    if prefix != "/v1/vulns" or not identifier or identifier in {".", ".."}:
        return False
    return all(character.isalnum() or character in "._:-" for character in identifier)


def normalize_osv_vulnerability(
    payload: Mapping[str, Any], *, retrieved_at: datetime, identifiers_only: bool = False
) -> tuple[SourceRecord | None, str | None]:
    identifier = canonical_identifier(payload.get("id"))
    if identifier is None:
        return None, "skipped_incomplete_entry"
    origin = dict(payload)
    aliases = []
    for item in payload.get("aliases") or []:
        found = canonical_identifier(item)
        if found and found != identifier:
            aliases.append(found)
    warnings: list[str] = []
    if identifiers_only or set(payload).issubset({"id", "modified", "withdrawn"}):
        warnings.append("detail_not_loaded")
        modified = parse_timestamp(payload.get("modified"))
        record = SourceRecord(
            source="osv",
            source_id=identifier,
            aliases=dedupe(aliases),
            title=None,
            summary=None,
            source_url=f"https://osv.dev/vulnerability/{quote(identifier, safe='')}",
            published_at=None,
            modified_at=modified,
            retrieved_at=retrieved_at,
            content_hash=content_hash(origin),
            references=[],
            affected=[],
            severity=[],
            known_exploited=None,
            license=None,
            attribution=_ATTRIBUTION,
            origin=origin,
            warnings=warnings,
            source_status=None,
        )
        return record, None
    affected: list[AffectedEntry] = []
    entries = payload.get("affected") or []
    if not isinstance(entries, list):
        warnings.append("unexpected_affected_shape")
        entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            warnings.append("skipped_incomplete_entry")
            continue
        package = entry.get("package") if isinstance(entry.get("package"), dict) else {}
        name = package.get("name") if isinstance(package, dict) else None
        ecosystem = package.get("ecosystem") if isinstance(package, dict) else None
        if not isinstance(name, str) or not name.strip():
            warnings.append("affected_package_name_missing")
            continue
        versions = entry.get("versions")
        version_list = (
            [item for item in versions if isinstance(item, str)]
            if isinstance(versions, list)
            else None
        )
        ranges = entry.get("ranges") if isinstance(entry.get("ranges"), list) else []
        affected.append(
            AffectedEntry(
                ecosystem=ecosystem if isinstance(ecosystem, str) else None,
                package_name=name.strip(),
                ranges=ranges,
                versions=version_list,
            )
        )
    severity: list[Severity] = []
    for item in payload.get("severity") or []:
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        severity.append(
            Severity(
                system=item.get("type") if isinstance(item.get("type"), str) else None,
                value=score if isinstance(score, str) else None,
                score=None,
                source="osv",
                raw=dict(item),
            )
        )
    published = parse_timestamp(payload.get("published"))
    modified = parse_timestamp(payload.get("modified"))
    if payload.get("published") and published is None:
        warnings.append("unparsed_timestamp")
    withdrawn = payload.get("withdrawn")
    summary = payload.get("details") if isinstance(payload.get("details"), str) else None
    title = payload.get("summary") if isinstance(payload.get("summary"), str) else None
    page = clean_reference(f"https://osv.dev/vulnerability/{quote(identifier, safe='')}")
    record = SourceRecord(
        source="osv",
        source_id=identifier,
        aliases=dedupe(aliases),
        title=title,
        summary=summary,
        source_url=page,
        published_at=published,
        modified_at=modified,
        retrieved_at=retrieved_at,
        content_hash=content_hash(origin),
        references=reference_list(payload.get("references")),
        affected=affected,
        affected_complete=bool(affected) and not warnings,
        severity=severity,
        known_exploited=None,
        license=payload.get("license") if isinstance(payload.get("license"), str) else None,
        attribution=_ATTRIBUTION,
        origin=origin,
        warnings=warnings,
        source_status="withdrawn" if withdrawn else "published",
    )
    return record, None


def query_osv(
    *,
    package_name: str | None = None,
    ecosystem: str | None = None,
    version: str | None = None,
    commit: str | None = None,
    page_token: str | None = None,
    cursor: str | None = None,
    transport: Transport | None = None,
    budget: WorkBudget | None = None,
    sleeper: Callable[[float], None] | None = None,
    now: Callable[[], datetime] | None = None,
) -> SourceBatch:
    """Query vulnerabilities for one package version or commit, following page tokens."""

    clock = now or (lambda: datetime.now(UTC))
    retrieved_at = clock()
    if cursor:
        state = load_cursor(cursor, source="osv", operation="query")
        body = state.get("body")
        if not isinstance(body, dict):
            raise SourceError(
                category="unsupported", source="osv", operation="query", reason="invalid_cursor"
            )
    else:
        body = _query_body(
            package_name=package_name, ecosystem=ecosystem, version=version, commit=commit
        )
        if page_token:
            body["page_token"] = page_token
    return _follow_query(
        body=body,
        retrieved_at=retrieved_at,
        transport=transport or UrllibTransport(),
        budget=budget or WorkBudget(),
        sleeper=sleeper or time.sleep,
        clock=clock,
    )


def query_osv_batch(
    queries: Sequence[Mapping[str, Any]],
    *,
    resolve_details: bool = False,
    cursor: str | None = None,
    max_queries: int = 100,
    transport: Transport | None = None,
    budget: WorkBudget | None = None,
    sleeper: Callable[[float], None] | None = None,
    now: Callable[[], datetime] | None = None,
) -> SourceBatch:
    """Batch query. Initial rows may contain only ids and modified timestamps.

    Set ``resolve_details`` to load ``GET /v1/vulns/{id}`` until the shared budget ends.
    Unfetched ids stay in the batch with ``detail_not_loaded`` and ``complete=False``.
    """

    clock = now or (lambda: datetime.now(UTC))
    retrieved_at = clock()
    worker = transport or UrllibTransport()
    limits = budget or WorkBudget()
    pause = sleeper or time.sleep
    if cursor:
        state = load_cursor(cursor, source="osv", operation="querybatch")
        operation = state.get("operation")
        if operation == "details":
            pending = state.get("ids")
            if not isinstance(pending, list):
                raise SourceError(
                    category="unsupported",
                    source="osv",
                    operation="querybatch",
                    reason="invalid_cursor",
                )
            records = [
                _placeholder(item, retrieved_at) for item in pending if isinstance(item, str)
            ]
            return _resolve(records, retrieved_at, worker, limits, pause, clock, [])
        raw_queries = state.get("queries")
        if not isinstance(raw_queries, list):
            raise SourceError(
                category="unsupported",
                source="osv",
                operation="querybatch",
                reason="invalid_cursor",
            )
        pending_queries = [item for item in raw_queries if isinstance(item, dict)]
    else:
        pending_queries = [dict(item) for item in queries]
    if max_queries < 1:
        raise SourceError(
            category="unsupported",
            source="osv",
            operation="querybatch",
            reason="invalid_batch_size",
        )
    records: list[SourceRecord] = []
    warnings: list[str] = ["identifiers_only"]
    while pending_queries:
        if limits.remaining_requests() <= 0 or limits.expired():
            warnings.append("budget_exceeded")
            return _batch(
                retrieved_at,
                records,
                False,
                _batch_cursor(pending_queries),
                warnings,
            )
        chunk = pending_queries[:max_queries]
        try:
            result = request_json(
                source="osv",
                operation="querybatch",
                method="POST",
                url="https://api.osv.dev/v1/querybatch",
                headers={},
                body={"queries": chunk},
                transport=worker,
                budget=limits,
                sleeper=pause,
                hosts=OSV_HOSTS,
                path_allowed=_path_allowed,
                now=clock,
            )
        except SourceError as error:
            if records:
                warnings.append(error.warning_code)
                return _batch(
                    retrieved_at, records, False, _batch_cursor(pending_queries), warnings
                )
            raise
        page_records, next_queries, page_warnings = _parse_batch_page(
            result.payload, chunk, retrieved_at
        )
        records.extend(page_records)
        warnings.extend(page_warnings)
        pending_queries = next_queries + pending_queries[max_queries:]
    if resolve_details:
        warnings = [item for item in warnings if item != "identifiers_only"]
        return _resolve(records, retrieved_at, worker, limits, pause, clock, warnings)
    if not records:
        warnings.append("empty_result_is_not_absence_of_risk")
    return _batch(retrieved_at, records, True, None, dedupe(warnings))


def fetch_osv_vulnerability(
    vulnerability_id: str,
    *,
    transport: Transport | None = None,
    budget: WorkBudget | None = None,
    sleeper: Callable[[float], None] | None = None,
    now: Callable[[], datetime] | None = None,
) -> SourceBatch:
    """Load one vulnerability, including a withdrawn record when OSV still stores it."""

    identifier = canonical_identifier(vulnerability_id)
    if identifier is None:
        raise SourceError(
            category="unsupported", source="osv", operation="get_vulnerability", reason="invalid_id"
        )
    clock = now or (lambda: datetime.now(UTC))
    retrieved_at = clock()
    result = request_json(
        source="osv",
        operation="get_vulnerability",
        method="GET",
        url=f"https://api.osv.dev/v1/vulns/{quote(identifier, safe='')}",
        headers={},
        body=None,
        transport=transport or UrllibTransport(),
        budget=budget or WorkBudget(),
        sleeper=sleeper or time.sleep,
        hosts=OSV_HOSTS,
        path_allowed=_path_allowed,
        now=clock,
    )
    if result.status_code == 404 or result.payload is None:
        return _batch(
            retrieved_at, [], True, None, ["not_found", "empty_result_is_not_absence_of_risk"]
        )
    if not isinstance(result.payload, dict):
        raise SourceError(
            category="invalid_response",
            source="osv",
            operation="get_vulnerability",
            reason="unexpected_shape",
        )
    record, warning = normalize_osv_vulnerability(result.payload, retrieved_at=retrieved_at)
    if record is None:
        raise SourceError(
            category="invalid_response",
            source="osv",
            operation="get_vulnerability",
            reason="unexpected_shape",
        )
    warnings = [warning] if warning else list(record.warnings)
    return _batch(retrieved_at, [record], True, None, dedupe(warnings))


def _query_body(
    *,
    package_name: str | None,
    ecosystem: str | None,
    version: str | None,
    commit: str | None,
) -> dict[str, Any]:
    if commit and version:
        raise SourceError(
            category="unsupported", source="osv", operation="query", reason="commit_and_version"
        )
    body: dict[str, Any] = {}
    if package_name or ecosystem:
        if not package_name or not ecosystem:
            raise SourceError(
                category="unsupported", source="osv", operation="query", reason="package_incomplete"
            )
        body["package"] = {"name": package_name, "ecosystem": ecosystem}
    if version:
        body["version"] = version
    if commit:
        body["commit"] = commit
    if not body:
        raise SourceError(
            category="unsupported", source="osv", operation="query", reason="query_empty"
        )
    return body


def _follow_query(
    *,
    body: dict[str, Any],
    retrieved_at: datetime,
    transport: Transport,
    budget: WorkBudget,
    sleeper: Callable[[float], None],
    clock: Callable[[], datetime],
) -> SourceBatch:
    records: list[SourceRecord] = []
    warnings: list[str] = []
    seen_tokens: set[str] = set()
    current = dict(body)
    while True:
        token = current.get("page_token")
        if isinstance(token, str):
            if token in seen_tokens:
                warnings.append("repeated_cursor")
                return _batch(retrieved_at, records, False, _query_cursor(current), warnings)
            seen_tokens.add(token)
        if budget.remaining_requests() <= 0 or budget.expired():
            warnings.append("budget_exceeded")
            return _batch(retrieved_at, records, False, _query_cursor(current), warnings)
        try:
            result = request_json(
                source="osv",
                operation="query",
                method="POST",
                url="https://api.osv.dev/v1/query",
                headers={},
                body=current,
                transport=transport,
                budget=budget,
                sleeper=sleeper,
                hosts=OSV_HOSTS,
                path_allowed=_path_allowed,
                now=clock,
            )
        except SourceError as error:
            if records:
                warnings.append(error.warning_code)
                return _batch(retrieved_at, records, False, _query_cursor(current), warnings)
            raise
        payload = result.payload
        if not isinstance(payload, dict) or not isinstance(payload.get("vulns"), list):
            if records:
                warnings.append("unexpected_shape")
                return _batch(retrieved_at, records, False, _query_cursor(current), warnings)
            raise SourceError(
                category="invalid_response",
                source="osv",
                operation="query",
                reason="unexpected_shape",
            )
        for item in payload["vulns"]:
            if not isinstance(item, dict):
                warnings.append("skipped_incomplete_entry")
                continue
            record, warning = normalize_osv_vulnerability(item, retrieved_at=retrieved_at)
            if warning:
                warnings.append(warning)
            if record is not None:
                records.append(record)
                warnings.extend(record.warnings)
        next_token = payload.get("next_page_token")
        if isinstance(next_token, str) and next_token:
            current = dict(current)
            current["page_token"] = next_token
            continue
        if not records:
            warnings.append("empty_result_is_not_absence_of_risk")
        return _batch(retrieved_at, records, True, None, dedupe(warnings))


def _parse_batch_page(
    payload: object, queries: Sequence[Mapping[str, Any]], retrieved_at: datetime
) -> tuple[list[SourceRecord], list[dict[str, Any]], list[str]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise SourceError(
            category="invalid_response",
            source="osv",
            operation="querybatch",
            reason="unexpected_shape",
        )
    results = payload["results"]
    if len(results) != len(queries):
        raise SourceError(
            category="invalid_response",
            source="osv",
            operation="querybatch",
            reason="result_count_mismatch",
        )
    records: list[SourceRecord] = []
    follow: list[dict[str, Any]] = []
    warnings: list[str] = []
    for query, result in zip(queries, results, strict=True):
        if not isinstance(result, dict) or not isinstance(result.get("vulns"), list):
            raise SourceError(
                category="invalid_response",
                source="osv",
                operation="querybatch",
                reason="unexpected_shape",
            )
        for item in result["vulns"]:
            if not isinstance(item, dict):
                warnings.append("skipped_incomplete_entry")
                continue
            record, warning = normalize_osv_vulnerability(item, retrieved_at=retrieved_at)
            if warning:
                warnings.append(warning)
            if record is not None:
                records.append(record)
        token = result.get("next_page_token")
        if isinstance(token, str) and token:
            follow.append({**query, "page_token": token})
    return records, follow, warnings


def _resolve(
    records: list[SourceRecord],
    retrieved_at: datetime,
    transport: Transport,
    budget: WorkBudget,
    sleeper: Callable[[float], None],
    clock: Callable[[], datetime],
    warnings: list[str],
) -> SourceBatch:
    resolved: list[SourceRecord] = []
    pending = list(records)
    while pending:
        current = pending[0]
        if "detail_not_loaded" not in current.warnings:
            resolved.append(pending.pop(0))
            continue
        if budget.remaining_requests() <= 0 or budget.expired():
            warnings.append("budget_exceeded")
            resolved.extend(pending)
            identifiers = [
                item.source_id for item in pending if "detail_not_loaded" in item.warnings
            ]
            cursor = dump_cursor(
                {"v": 1, "source": "osv", "operation": "details", "ids": identifiers}
            )
            return _batch(retrieved_at, resolved, False, cursor, dedupe(warnings))
        try:
            detail = fetch_osv_vulnerability(
                current.source_id,
                transport=transport,
                budget=budget,
                sleeper=sleeper,
                now=clock,
            )
        except SourceError as error:
            warnings.append(error.warning_code)
            resolved.extend(pending)
            identifiers = [item.source_id for item in pending]
            cursor = dump_cursor(
                {"v": 1, "source": "osv", "operation": "details", "ids": identifiers}
            )
            return _batch(retrieved_at, resolved, False, cursor, dedupe(warnings))
        pending.pop(0)
        if detail.records:
            resolved.append(detail.records[0])
        else:
            warnings.append("not_found")
            resolved.append(current)
    return _batch(retrieved_at, resolved, True, None, dedupe(warnings))


def _placeholder(identifier: str, retrieved_at: datetime) -> SourceRecord:
    origin = {"id": identifier}
    record, _warning = normalize_osv_vulnerability(
        origin, retrieved_at=retrieved_at, identifiers_only=True
    )
    if record is None:
        raise SourceError(
            category="unsupported", source="osv", operation="querybatch", reason="invalid_id"
        )
    return record


def _query_cursor(body: Mapping[str, Any]) -> str:
    return dump_cursor({"v": 1, "source": "osv", "operation": "query", "body": dict(body)})


def _batch_cursor(queries: Sequence[Mapping[str, Any]]) -> str:
    return dump_cursor(
        {
            "v": 1,
            "source": "osv",
            "operation": "querybatch",
            "queries": [dict(item) for item in queries],
        }
    )


def _batch(
    retrieved_at: datetime,
    records: list[SourceRecord],
    complete: bool,
    cursor: str | None,
    warnings: list[str],
) -> SourceBatch:
    return SourceBatch(
        source="osv",
        retrieved_at=retrieved_at,
        records=records,
        complete=complete,
        next_cursor=cursor,
        warnings=dedupe(warnings),
    )
