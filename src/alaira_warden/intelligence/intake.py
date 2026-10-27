"""Manual intake, consultation summary, and cursor resume. No scheduler is started."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from alaira_warden.intelligence.errors import SourceError
from alaira_warden.intelligence.github import fetch_github_advisories
from alaira_warden.intelligence.hashing import content_hash
from alaira_warden.intelligence.http import Transport, WorkBudget
from alaira_warden.intelligence.kev import fetch_kev_catalog
from alaira_warden.intelligence.models import (
    Attribution,
    ConsultationReport,
    SourceAttempt,
    SourceBatch,
    SourceRecord,
    SyncPlan,
)
from alaira_warden.intelligence.nvd import fetch_nvd_cve, fetch_nvd_modified
from alaira_warden.intelligence.osv import query_osv, query_osv_batch
from alaira_warden.intelligence.textutil import (
    canonical_identifier,
    clean_reference,
    dump_cursor,
    load_cursor,
    require_aware,
)

_MANUAL = Attribution(
    provider="manual intake",
    documentation_url="urn:alaira-warden:manual-advisory",
    notes="Operator-supplied report. It is not a result from GitHub, OSV, NVD, or CISA KEV.",
)

_LIMITATIONS = {
    "github": (
        "Public listing excludes malware unless type=malware. Private repositories "
        "are outside this client. An empty page is not proof of safety."
    ),
    "osv": "An empty OSV result does not prove the inventory is complete or risk-free.",
    "nvd": "CPE and NVD affected-product data are not npm package identities.",
    "cisa-kev": "Absence from KEV does not show that a vulnerability is not exploited.",
    "manual": "A manual report is unverified intake, not corroboration by the four catalogs.",
}


def manual_advisory(
    *,
    source_url: str,
    description: str,
    received_at: datetime,
    title: str | None = None,
    identifier: str | None = None,
    retrieved_at: datetime | None = None,
) -> SourceRecord:
    """RF-09 intake. A missing CVE is valid. No catalog is queried and no URL is fetched."""

    if not description.strip():
        raise SourceError(
            category="unsupported",
            source="manual",
            operation="intake",
            reason="description_required",
        )
    url = clean_reference(source_url)
    if url is None:
        raise SourceError(
            category="unsupported", source="manual", operation="intake", reason="invalid_source_url"
        )
    received = require_aware(received_at, source="manual", operation="intake")
    observed = retrieved_at or datetime.now(UTC)
    observed = require_aware(observed, source="manual", operation="intake")
    canonical = canonical_identifier(identifier) if identifier else None
    if identifier and canonical is None:
        raise SourceError(
            category="unsupported", source="manual", operation="intake", reason="invalid_identifier"
        )
    source_id = (
        canonical
        or "manual:" + content_hash({"url": url, "received_at": received.isoformat()})[:32]
    )
    origin = {
        "source_url": url,
        "description": description.strip(),
        "received_at": received.isoformat(),
        "title": title,
        "identifier": canonical,
    }
    aliases = [canonical] if canonical and canonical != source_id else []
    return SourceRecord(
        source="manual",
        source_id=source_id,
        aliases=aliases,
        title=title.strip() if isinstance(title, str) and title.strip() else None,
        summary=description.strip(),
        source_url=url,
        published_at=None,
        modified_at=None,
        retrieved_at=observed,
        content_hash=content_hash(origin),
        references=[url],
        affected=[],
        severity=[],
        known_exploited=None,
        license=None,
        attribution=_MANUAL,
        origin=origin,
        warnings=["manual_intake_unverified"],
        received_at=received,
    )


def consultation_report(
    batches: Sequence[SourceBatch] = (),
    errors: Sequence[SourceError] = (),
) -> ConsultationReport:
    """Summarize attempts the caller already made. This does not query sources."""

    attempts: list[SourceAttempt] = []
    for batch in batches:
        attempts.append(
            SourceAttempt(
                source=batch.source,
                operation="batch",
                ok=True,
                complete=batch.complete,
                record_count=len(batch.records),
                warnings=list(batch.warnings),
                limitations=[_LIMITATIONS.get(batch.source, "")],
            )
        )
    for error in errors:
        attempts.append(
            SourceAttempt(
                source=error.source,
                operation=error.operation,
                ok=False,
                complete=False,
                error_category=error.category,
                warnings=[error.warning_code],
                limitations=[_LIMITATIONS.get(error.source, "")],
            )
        )
    unverified = [
        "Failed attempts are not evidence that a vulnerability is absent.",
        "Copied identifiers across catalogs are not independent corroboration.",
        "Reference URLs were not downloaded.",
    ]
    return ConsultationReport(attempts=attempts, unverified=unverified)


def default_sync_plan() -> tuple[SyncPlan, ...]:
    """Poll hints for the integrator. Nothing in this package runs them."""

    return (
        SyncPlan(
            source="github",
            operation="list_advisories",
            interval_seconds=3600,
            notes=(
                "List npm reviewed and malware advisories with updated>=cursor time. "
                "Unauthenticated REST limit is 60 requests/hour."
            ),
        ),
        SyncPlan(
            source="osv",
            operation="package_query",
            interval_seconds=None,
            notes=(
                "The query API has page tokens, not a modified-since cursor. Drive it "
                "from inventory package versions. Do not treat an empty result as safety."
            ),
        ),
        SyncPlan(
            source="nvd",
            operation="modified_window",
            interval_seconds=7200,
            notes=(
                "NVD recommends maintaining the local set no more than once every two "
                "hours and sleeping about six seconds between requests. Windows are "
                "capped at 119 days."
            ),
        ),
        SyncPlan(
            source="cisa-kev",
            operation="catalog",
            interval_seconds=3600,
            notes=(
                "Each poll downloads the full catalog. Skip reprocessing when "
                "catalog_unchanged is set. A miss is not proof of no exploitation."
            ),
        ),
    )


def resume(
    cursor: str,
    *,
    github_token: str | None = None,
    nvd_api_key: str | None = None,
    transport: Transport | None = None,
    budget: WorkBudget | None = None,
    sleeper=None,
    now=None,
) -> SourceBatch:
    """Continue a cursor produced by this package. The cursor selects the client."""

    try:
        payload = load_cursor(cursor, source="resume", operation="resume")
    except SourceError:
        payload = None
    if payload is None:
        import json

        try:
            payload = json.loads(cursor)
        except json.JSONDecodeError:
            raise SourceError(
                category="unsupported", source="resume", operation="resume", reason="invalid_cursor"
            ) from None
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise SourceError(
            category="unsupported", source="resume", operation="resume", reason="invalid_cursor"
        )
    source = payload.get("source")
    operation = payload.get("operation")
    common = {"transport": transport, "budget": budget, "sleeper": sleeper, "now": now}
    if source == "github":
        return fetch_github_advisories(cursor=cursor, github_token=github_token, **common)
    if source == "osv" and operation == "query":
        return query_osv(cursor=cursor, **common)
    if source == "osv":
        return query_osv_batch((), cursor=cursor, resolve_details=operation == "details", **common)
    if source == "nvd" and operation == "cve_history":
        cve_id = payload.get("cve_id")
        start = payload.get("start_index") if isinstance(payload.get("start_index"), int) else 0
        if not isinstance(cve_id, str):
            raise SourceError(
                category="unsupported",
                source="nvd",
                operation="cve_history",
                reason="invalid_cursor",
            )
        return fetch_nvd_cve(
            cve_id,
            nvd_api_key=nvd_api_key,
            include_changes=True,
            history_start=start,
            **common,
        )
    if source == "nvd":
        return fetch_nvd_modified(
            modified_since=datetime.now(UTC),
            cursor=cursor,
            nvd_api_key=nvd_api_key,
            **common,
        )
    if source == "cisa-kev":
        return fetch_kev_catalog(cursor=cursor, **common)
    raise SourceError(
        category="unsupported",
        source="resume",
        operation="resume",
        reason="cursor_source_unsupported",
    )


def encode_cursor(payload: dict) -> str:
    return dump_cursor(payload)
