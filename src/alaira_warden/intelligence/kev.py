"""CISA Known Exploited Vulnerabilities catalog.

Documentation consulted on 2026-10-26:
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The feed is one JSON document. There is no delta API. A repeated ``catalogVersion``
returns no records and the warning ``catalog_unchanged``; that is not an empty
catalog and it is not proof that other vulnerabilities are unexploited. Vendor and
product names are not npm package identities. A CVE that is absent from a loaded
catalog leaves ``known_exploited`` null.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime

from alaira_warden.intelligence.errors import SourceError
from alaira_warden.intelligence.hashing import content_hash
from alaira_warden.intelligence.http import Transport, UrllibTransport, WorkBudget, request_json
from alaira_warden.intelligence.models import (
    Attribution,
    KevLookup,
    KnownExploited,
    SourceBatch,
    SourceRecord,
)
from alaira_warden.intelligence.textutil import (
    CVE_RE,
    canonical_identifier,
    dedupe,
    dump_cursor,
    load_cursor,
    parse_timestamp,
    require_aware,
    urls_in_text,
)

KEV_HOSTS = frozenset({"www.cisa.gov"})
FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
DOCS = CATALOG_URL
_ATTRIBUTION = Attribution(
    provider="CISA Known Exploited Vulnerabilities Catalog",
    documentation_url=DOCS,
    notes=(
        "Public CISA catalog. Confirm the catalog License page before redistributing "
        "the feed. Absence of a CVE does not demonstrate that it is not exploited. "
        "vendorProject and product are not npm package names."
    ),
)


def _path_allowed(path: str) -> bool:
    return path == "/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_catalog(
    *,
    added_since: datetime | None = None,
    cursor: str | None = None,
    transport: Transport | None = None,
    budget: WorkBudget | None = None,
    sleeper: Callable[[float], None] | None = None,
    now: Callable[[], datetime] | None = None,
) -> SourceBatch:
    """Download the catalog. ``added_since`` filters ``dateAdded`` and is not a delta."""

    clock = now or (lambda: datetime.now(UTC))
    retrieved_at = clock()
    previous_version = None
    if cursor:
        state = load_cursor(cursor, source="cisa-kev", operation="catalog")
        previous_version = state.get("catalog_version")
        if not isinstance(previous_version, str):
            raise SourceError(
                category="unsupported", source="cisa-kev", operation="catalog",
                    reason="invalid_cursor"
            )
    if added_since is not None:
        added_since = require_aware(added_since, source="cisa-kev", operation="catalog")
    result = request_json(
        source="cisa-kev",
        operation="catalog",
        method="GET",
        url=FEED_URL,
        headers={},
        body=None,
        transport=transport or UrllibTransport(),
        budget=budget or WorkBudget(),
        sleeper=sleeper or time.sleep,
        hosts=KEV_HOSTS,
        path_allowed=_path_allowed,
        now=clock,
    )
    payload = result.payload
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise SourceError(
            category="invalid_response", source="cisa-kev", operation="catalog",
                reason="unexpected_shape"
        )
    version = payload.get("catalogVersion")
    if not isinstance(version, str) or not version.strip():
        raise SourceError(
            category="invalid_response", source="cisa-kev", operation="catalog",
                reason="unexpected_shape"
        )
    next_cursor = dump_cursor(
        {
            "v": 1,
            "source": "cisa-kev",
            "catalog_version": version,
            "date_released": payload.get("dateReleased"),
        }
    )
    if previous_version == version:
        return SourceBatch(
            source="cisa-kev",
            retrieved_at=retrieved_at,
            records=[],
            complete=True,
            next_cursor=next_cursor,
            warnings=["catalog_unchanged"],
        )
    warnings: list[str] = []
    released = parse_timestamp(payload.get("dateReleased"))
    if payload.get("dateReleased") and released is None:
        warnings.append("unparsed_timestamp")
    records: list[SourceRecord] = []
    for entry in payload["vulnerabilities"]:
        if not isinstance(entry, dict):
            warnings.append("skipped_incomplete_entry")
            continue
        record, warning = normalize_kev_entry(
            entry,
            retrieved_at=retrieved_at,
            catalog_version=version,
            date_released=payload.get("dateReleased") if isinstance(payload.get("dateReleased"),
                str) else None,
        )
        if warning:
            warnings.append(warning)
        if record is None:
            continue
        if added_since is not None and (record.published_at is None
            or record.published_at < added_since):
            if record.published_at is None:
                warnings.append("unparsed_timestamp")
            continue
        records.append(record)
        warnings.extend(record.warnings)
    count = payload.get("count")
    complete = True
    if isinstance(count, int) and count != len(payload["vulnerabilities"]):
        warnings.append("catalog_count_mismatch")
        complete = False
    if added_since is not None:
        warnings.append("date_added_filter_is_not_a_complete_delta")
    if not records and added_since is None:
        warnings.append("empty_result_is_not_absence_of_risk")
    return SourceBatch(
        source="cisa-kev",
        retrieved_at=retrieved_at,
        records=records,
        complete=complete,
        next_cursor=next_cursor,
        warnings=dedupe(warnings),
    )


def normalize_kev_entry(
    entry: dict,
    *,
    retrieved_at: datetime,
    catalog_version: str,
    date_released: str | None,
) -> tuple[SourceRecord | None, str | None]:
    identifier = canonical_identifier(entry.get("cveID"))
    if identifier is None or not CVE_RE.fullmatch(identifier):
        return None, "skipped_incomplete_entry"
    added = parse_timestamp(entry.get("dateAdded"))
    warnings = ["kev_has_no_npm_package_identity"]
    if entry.get("dateAdded") and added is None:
        warnings.append("unparsed_timestamp")
    notes = entry.get("notes") if isinstance(entry.get("notes"), str) else None
    references = dedupe([FEED_URL, *urls_in_text(notes)])
    origin = dict(entry)
    origin["catalogVersion"] = catalog_version
    if date_released is not None:
        origin["dateReleased"] = date_released
    ransomware = entry.get("knownRansomwareCampaignUse")
    known = KnownExploited(
        known=True,
        source="cisa-kev",
        catalog_version=catalog_version,
        date_added=added,
        ransomware_use=ransomware if isinstance(ransomware, str) else None,
        detail=entry.get("requiredAction") if isinstance(entry.get("requiredAction"),
            str) else None,
    )
    title = entry.get("vulnerabilityName") if isinstance(entry.get("vulnerabilityName"),
        str) else identifier
    summary = entry.get("shortDescription") if isinstance(entry.get("shortDescription"),
        str) else None
    record = SourceRecord(
        source="cisa-kev",
        source_id=identifier,
        aliases=[],
        title=title,
        summary=summary,
        source_url=FEED_URL,
        published_at=added,
        modified_at=parse_timestamp(date_released) if date_released else None,
        retrieved_at=retrieved_at,
        content_hash=content_hash(origin),
        references=references,
        affected=[],
        severity=[],
        known_exploited=known,
        license=None,
        attribution=_ATTRIBUTION,
        origin=origin,
        warnings=warnings,
    )
    return record, None


def lookup_kev(batch: SourceBatch, cve_id: str) -> KevLookup:
    """Find a CVE in an already downloaded catalog. A miss is unknown, not safe."""

    identifier = canonical_identifier(cve_id)
    if identifier is None or not CVE_RE.fullmatch(identifier):
        raise SourceError(
            category="unsupported", source="cisa-kev", operation="lookup", reason="invalid_cve_id"
        )
    if batch.source != "cisa-kev":
        raise SourceError(
            category="unsupported", source="cisa-kev", operation="lookup", reason="not_a_kev_batch"
        )
    for record in batch.records:
        if record.source_id == identifier or identifier in record.aliases:
            return KevLookup(
                cve_id=identifier, found=True, known_exploited=record.known_exploited, record=record
            )
    return KevLookup(cve_id=identifier, found=False, known_exploited=None, record=None)


def index_kev(batch: SourceBatch) -> dict[str, SourceRecord]:
    if batch.source != "cisa-kev":
        raise SourceError(
            category="unsupported", source="cisa-kev", operation="lookup", reason="not_a_kev_batch"
        )
    return {record.source_id: record for record in batch.records}
