import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/acceptance_report.py"
spec = importlib.util.spec_from_file_location("acceptance_report", SCRIPT)
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)


def test_missing_evidence_cannot_become_acceptance(tmp_path):
    report = reporter.build_report(tmp_path)
    assert report["acceptance_verified"] is False
    assert {row["id"] for row in report["criteria"]} == {f"CA-{n:02}" for n in range(1, 18)}
    assert all(row["status"] == "unproven" for row in report["criteria"])
    assert all(row["status"] == "unproven" for row in report["artifacts"].values())


def test_passing_probe_is_component_proof_only(tmp_path):
    path = tmp_path / reporter.ARTIFACTS["nightshift_probe"]
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "nightshift_deployment_verified": True,
                "returned_model": "nvidia/model",
                "secret": "never-export",
            }
        )
    )
    report = reporter.build_report(tmp_path)
    assert report["artifacts"]["nightshift_probe"]["status"] == "passed"
    assert report["criteria"][15]["status"] == "unproven"
    assert "never-export" not in json.dumps(report)


def test_invalid_artifact_is_unproven_and_failed_remediation_is_not_accepted(tmp_path):
    path = tmp_path / reporter.ARTIFACTS["remediation"]
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"status": "failed", "validated": False}))
    summary = reporter.build_report(tmp_path)["artifacts"]["remediation"]
    assert summary["status"] == "unproven"
    path.write_text("not JSON")
    assert (
        reporter.build_report(tmp_path)["artifacts"]["remediation"]["reason"] == "invalid_artifact"
    )
