"""Opt-in complete real Git/npm/scanner workflow with public fixture dependencies."""

import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from alaira_warden.execution import DockerRunner, Limits
from alaira_warden.remediation import remediate, verify_artifact
from alaira_warden.remediation.tools import npm_tools, scanner_tools
from tests.test_remediation_pipeline import git, prepared  # noqa: F401

pytestmark = pytest.mark.skipif(
    os.getenv("WARDEN_RUN_REMEDIATION_SCANNER_TESTS") != "1",
    reason="Requires operator-built scanner image with real offline databases",
)


@pytest.mark.parametrize("test_failure", [False, True])
def test_real_scanners_on_proposed_commit(prepared, test_failure):  # noqa: F811
    request, policy = prepared
    manifest_path = request.repository / "package.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scripts"] = {"test": "node test.js"}
    manifest_path.write_text(json.dumps(manifest))
    (request.repository / "test.js").write_text(
        "process.exit(7);\n"
        if test_failure
        else "require('node:assert/strict').equal("
        "require('lodash/package.json').version,'4.18.1');\n"
    )
    git(request.repository, "add", ".")
    git(request.repository, "commit", "-m", "Add candidate version test")
    request = replace(
        request,
        base_sha=git(request.repository, "rev-parse", "HEAD"),
        versions=("4.18.1", "4.17.21"),
        max_attempts=1,
        timeout_seconds=900,
    )
    image = subprocess.check_output(
        ["docker", "image", "inspect", "alaira-warden-remediation-tools", "--format", "{{.Id}}"],
        text=True,
    ).strip()
    tools = {
        **npm_tools(image),
        **scanner_tools(syft_image=image, trivy_image=image, osv_image=image),
    }
    limits = replace(
        Limits(),
        memory_mb=2048,
        temporary_mb=64,
        workspace_mb=128,
        timeout_seconds=180,
        files=1024,
        artifact_bytes=16 * 1024 * 1024,
    )
    runner = DockerRunner(replace(policy, tools=tools, limits=limits))
    report = remediate(
        request, runner, authorized_repositories={request.application_id: request.repository}
    )
    proof_root = Path(__file__).resolve().parents[1] / "artifacts"
    durable = proof_root / "remediation-e2e" / report["id"]
    shutil.copytree(request.repository, durable / "repository")
    shutil.copytree(runner.policy.artifact_root, durable / "jobs")
    report["proof_repository"] = str(durable / "repository")
    report["proof_artifacts"] = str(durable / "jobs")
    proof_name = "remediation-failed-e2e.json" if test_failure else "remediation-full-e2e.json"
    (proof_root / proof_name).write_text(json.dumps(report, indent=2, default=str))
    assert len(report["attempts"]) == 1
    assert len(report["attempts"][0]["validations"]) == 4
    if test_failure:
        assert report["status"] == "failed", report
        assert report["validated"] is False
        assert report["stop_reason"] == "attempt_limit_or_candidates_exhausted"
        assert report["attempts"][0]["validations"][0]["status"] == "failed"
        with pytest.raises(ValueError):
            verify_artifact(report, request.repository)
    else:
        assert report["status"] == "passed", report
        assert report["validated"] is True
        assert "4.18.1" in verify_artifact(report, durable / "repository")["package-lock.json"]
