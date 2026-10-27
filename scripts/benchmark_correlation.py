"""Synthetic RNF-09 probe. No source queries, models or private data."""

import json
import math
import platform
import statistics
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from alaira_warden.correlation import evaluate_snapshot
from alaira_warden.correlation.models import (
    Advisory,
    Component,
    PackageRule,
    Snapshot,
    VersionRange,
)


def benchmark() -> dict:
    observed = datetime.now(UTC)
    snapshot = Snapshot(
        id=uuid4(),
        application_id=uuid4(),
        commit_sha="a" * 40,
        observed_at=observed,
        completeness="complete",
        components=tuple(
            Component(id=f"synthetic-{number}", name="fixture", resolved_version=f"1.0.{number}")
            for number in range(10000)
        ),
    )
    advisory = Advisory(
        source="synthetic",
        source_id="BENCHMARK-NOT-A-REAL-ADVISORY",
        content_hash="b" * 64,
        evidence_status="confirmed",
        affected_complete=True,
        affected=(
            PackageRule(
                ecosystem="npm",
                package_name="fixture",
                ranges=(VersionRange(type="npm", expression="<1.0.5000"),),
            ),
        ),
    )
    durations = []
    for _ in range(20):
        start = perf_counter()
        result = evaluate_snapshot(snapshot, advisory, now=observed)
        durations.append(perf_counter() - start)
        assert sum(finding.version_affected is True for finding in result.findings) == 5000
        assert sum(finding.version_affected is False for finding in result.findings) == 5000
    percentile = sorted(durations)[math.ceil(len(durations) * 0.95) - 1]
    return {
        "checked_at": datetime.now(UTC).isoformat(),
        "synthetic": True,
        "platform": platform.system(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "components": 10000,
        "advisories": 1,
        "executions": 20,
        "durations_seconds": durations,
        "median_seconds": statistics.median(durations),
        "p95_seconds": percentile,
        "target_seconds": 60,
        "passed": percentile <= 60,
        "scope": "Local correlation only; excludes ingestion, model calls and persistent storage.",
    }


if __name__ == "__main__":
    report = benchmark()
    directory = Path(__file__).resolve().parents[1] / "artifacts" / "correlation"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "benchmark.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
