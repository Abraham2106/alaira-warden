"""Explicit boundary between source-shaped records and deterministic correlation."""

from uuid import UUID

from alaira_warden.correlation.models import (
    Advisory,
    Component,
    PackageRule,
    Snapshot,
    VersionRange,
)
from alaira_warden.intelligence import SourceRecord


def advisory(record: SourceRecord, confidence: str = "preliminary") -> Advisory:
    packages = []
    for affected in record.affected:
        if not affected.package_name or not affected.ecosystem:
            continue
        ranges = []
        for item in affected.ranges:
            if not isinstance(item, dict):
                ranges.append(VersionRange(type="unsupported"))
            elif item.get("type") == "github_vulnerable_version_range":
                expression = item.get("vulnerable_version_range")
                ranges.append(VersionRange(type="npm", expression=expression))
            elif item.get("type") == "SEMVER" and isinstance(item.get("events"), list):
                ranges.append(VersionRange(type="SEMVER", events=tuple(item["events"])))
            else:
                ranges.append(VersionRange(type="unsupported"))
        packages.append(
            PackageRule(
                ecosystem=affected.ecosystem,
                package_name=affected.package_name,
                ranges=tuple(ranges),
                versions=tuple(affected.versions or ()),
            )
        )
    scores = [
        item.score
        for item in record.severity
        if item.score is not None
        and 0 <= item.score <= 10
        and item.system
        and item.system.upper().startswith("CVSS")
    ]
    return Advisory(
        source=record.source,
        source_id=record.source_id,
        content_hash=record.content_hash,
        affected=tuple(packages),
        affected_complete=record.affected_complete,
        evidence_status=confidence,
        severity_score=max(scores) if scores else None,
        known_exploited=record.known_exploited.known if record.known_exploited else None,
        withdrawn=record.source_status in {"withdrawn", "rejected"},
    )


def snapshot(row: dict, components: list[dict]) -> Snapshot:
    return Snapshot(
        id=UUID(str(row["id"])),
        application_id=row["application_id"],
        commit_sha=row["commit_ref"],
        observed_at=row["observed_at"],
        completeness=row["completeness"],
        components=tuple(
            Component(
                id=str(item["id"]),
                name=item["name"],
                ecosystem=item["ecosystem"],
                resolved_version=item["resolved_version"],
                dependency_paths=tuple(tuple(path) for path in item["dependency_paths"]),
            )
            for item in components
        ),
    )
