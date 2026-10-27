"""Inventory acceptance evidence without equating component proof with MVP acceptance.

Reads only the explicitly listed public/synthetic JSON artifacts. Does not read
configuration, credentials, logs, databases, network services, or private files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# A passing component artifact supports a criterion; it never closes it.
CA = (
    ("Direct dependency", "Direct affected package, asset, reference and finding", "01"),
    ("Transitive dependency", "Transitive path visible in an integrated case", "02"),
    ("Out-of-range version", "Not affected with evidence and no unnecessary patch", "03"),
    ("Insufficient evidence", "Missing inputs cause explicit uncertainty", "04"),
    ("Historical exposure", "Safe current snapshot retains vulnerable deployment follow-up", "05"),
    ("Valid correction", "Exact commit passes tools and yields a human-authorized real PR", "06"),
    (
        "Failed correction",
        "Real failure exhausts bounded retries without success declaration",
        "07",
    ),
    ("Forbidden action", "Merge/deploy/production-secret denial is audited", "08"),
    ("Stale approval", "Commit or destination change invalidates persisted authorization", "09"),
    ("Recovery and duplicates", "Process restart during publish preserves one case and PR", "10"),
    ("Source failure", "Down/contradictory sources preserve state and communicate limits", "11"),
    ("Complete audit", "Report reconstructs actual changes, validations and human decision", "12"),
    ("Untrusted instructions", "Malicious source content cannot expand tools or permissions", "13"),
    ("Zetaris data layer", "Named data reads feed the integrated investigation", "14"),
    ("H-MEM Engine", "Conformance plus scoped prior-case recall without exposure mutation", "15"),
    ("Nightshift synthesis", "Principal synthesis produces usable output with actual model", "16"),
    ("Credential-free sample", "Labeled example runs without sponsor credentials or calls", "17"),
)

ARTIFACTS = {
    "sample": "artifacts/sample/cases.json",
    "hmem_conformance": "artifacts/hmem-conformance.json",
    "nightshift_probe": "artifacts/nightshift-e2e.json",
    "zetaris_read": "artifacts/zetaris/e2e.json",
    "remediation": "artifacts/remediation-full-e2e.json",
}


def artifact_summary(root: Path, name: str, relative: str) -> dict:
    path = root / relative
    summary = {"path": relative, "status": "unproven", "scope": "component artifact"}
    if not path.is_file():
        return {**summary, "reason": "artifact_missing"}
    raw = path.read_bytes()
    summary["sha256"] = hashlib.sha256(raw).hexdigest()
    summary["modified_at"] = datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat()
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("expected object")
    except (ValueError, UnicodeDecodeError):
        return {**summary, "reason": "invalid_artifact"}
    # Report only booleans/counts/model and named sources, never arbitrary text/output.
    if name == "sample":
        passed = (
            data.get("synthetic") is True
            and data.get("credentials_used") is False
            and data.get("sponsors_verified") is False
            and len(data.get("results", [])) >= 3
        )
    elif name == "hmem_conformance":
        passed = data.get("verified") is True and data.get("passed") == data.get("total", 0) > 0
        summary["passed_vectors"] = data.get("passed")
    elif name == "nightshift_probe":
        passed = data.get("nightshift_deployment_verified") is True
        summary["model"] = data.get("returned_model")
        summary["scope"] = "generation probe; not proof of principal case synthesis"
    elif name == "zetaris_read":
        passed = data.get("sponsor_data_layer_verified") is True and bool(data.get("data_sources"))
        summary["scope"] = "named read and assessment script; not full UI case"
    else:
        passed = data.get("validated") is True and data.get("status") == "passed"
        summary["scope"] = "local remediation; not approval or published PR"
        summary["execution_status"] = data.get("status")
    return {**summary, "status": "passed" if passed else "unproven"}


def build_report(root: Path = ROOT) -> dict:
    artifacts = {name: artifact_summary(root, name, path) for name, path in ARTIFACTS.items()}
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "kind": "acceptance_evidence_inventory",
        "acceptance_verified": False,
        "warning": "Artifact observations do not establish acceptance of CA-01–CA-17.",
        "criteria": [
            {
                "id": f"CA-{number}",
                "scenario": name,
                "status": "unproven",
                "required_end_to_end_proof": proof,
            }
            for name, proof, number in CA
        ],
        "artifacts": artifacts,
        "checks_not_run": [
            {"name": name, "status": "skipped"}
            for name in (
                "clean-machine installation",
                "live sponsor execution",
                "production database",
                "real GitHub PR publication",
                "browser visual review",
                "full CA end-to-end suite",
            )
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/acceptance/report.json")
    args = parser.parse_args()
    report = build_report()
    git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    report["observed_commit"] = git.stdout.strip() if git.returncode == 0 else None
    # Do not print paths/names of untracked files: those may name private artifacts.
    dirty = subprocess.run(["git", "diff", "--quiet", "HEAD"], cwd=ROOT, capture_output=True)
    report["tracked_changes_present"] = dirty.returncode != 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Evidence inventory written to {args.output}; MVP acceptance remains unproven.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
