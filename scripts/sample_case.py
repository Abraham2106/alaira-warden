"""Credential-free deterministic examples. Synthetic inputs never claim sponsor execution."""

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from alaira_warden.correlation.engine import evaluate_snapshot
from alaira_warden.correlation.models import (
    Advisory,
    Component,
    PackageRule,
    Snapshot,
    VersionRange,
)


def sample():
    now = datetime.now(UTC)
    notice = Advisory(
        source="synthetic",
        source_id="SAMPLE-ONLY",
        content_hash="a" * 64,
        affected_complete=True,
        evidence_status="confirmed",
        affected=(
            PackageRule(
                ecosystem="npm",
                package_name="example-package",
                ranges=(VersionRange(type="npm", expression="<2.0.0"),),
            ),
        ),
    )
    results = []
    for version, completeness, expected in (
        ("1.0.0", "complete", "potential"),
        ("2.0.0", "complete", "not_affected"),
        ("2.0.0", "partial", "undetermined"),
    ):
        snapshot = Snapshot(
            id=uuid4(),
            application_id=uuid4(),
            commit_sha="b" * 40,
            observed_at=now,
            completeness=completeness,
            components=(
                Component(
                    id=str(uuid4()),
                    name="example-package",
                    ecosystem="npm",
                    resolved_version=version,
                    dependency_paths=((f"example-package@{version}",),),
                ),
            ),
        )
        result = evaluate_snapshot(snapshot, notice, now=now)
        assert result.exposure == expected, "Sample comparison failed; check npm ci and Node."
        results.append(result.model_dump(mode="json"))
    return {
        "mode": "sample",
        "synthetic": True,
        "credentials_used": False,
        "sponsors_verified": False,
        "ai_generation": False,
        "results": results,
    }


if __name__ == "__main__":
    destination = Path("artifacts/sample/cases.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(sample(), indent=2), encoding="utf-8")
    print(f"Three synthetic cases passed. No sponsor calls. Output: {destination}")
