"""Real Git objects with controlled executor results; not scanner integration proof."""

import hashlib
import json
import subprocess
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from alaira_warden.execution import ExecutionPolicy, JobResult, Limits, Tool
from alaira_warden.execution.models import Artifact
from alaira_warden.remediation import RemediationRequest, remediate, verify_artifact


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


@pytest.fixture
def prepared(tmp_path):
    repo = tmp_path / "repository"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@localhost")
    manifest = {"name": "fixture", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}}
    lock = {
        "name": "fixture",
        "lockfileVersion": 3,
        "packages": {"": manifest, "node_modules/lodash": {"version": "4.17.20"}},
    }
    (repo / "package.json").write_text(json.dumps(manifest))
    (repo / "package-lock.json").write_text(json.dumps(lock))
    # Snapshot must not honor export-ignore and accidentally omit tests from validation.
    (repo / ".gitattributes").write_text("test.js export-ignore\n")
    (repo / "test.js").write_text("console.log('fixture')\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "Fixture")
    base = git(repo, "rev-parse", "HEAD")
    app = uuid4()
    request = RemediationRequest(app, "fixture-actor", repo, base, "lodash", ("4.17.21",))
    root = tmp_path / "input"
    root.mkdir()
    tools = {
        name: Tool("sha256:" + "a" * 64, "/bin/true")
        for name in ("npm_lockfile", "project_tests", "syft", "trivy", "osv_scanner")
    }
    policy = ExecutionPolicy(root, tmp_path / "output", frozenset({app}), tools, Limits())
    return request, policy


class ControlledRunner:
    def __init__(self, policy, failed_tool=None):
        self.policy, self.failed_tool = policy, failed_tool
        self.jobs = []

    def run(self, job, cancel=None):
        self.jobs.append(job)
        assert (job.source / "test.js").is_file()
        job_id = uuid4().hex
        folder = self.policy.artifact_root / job_id / "files"
        folder.mkdir(parents=True)
        files = {}
        if job.tool == "npm_lockfile":
            for name in ("package.json", "package-lock.json"):
                content = (job.source / name).read_text().replace("4.17.20", job.arguments[1])
                files[name] = content.encode()
        elif job.tool != "project_tests":
            name = {"syft": "syft.json", "trivy": "trivy.json", "osv_scanner": "osv.json"}[job.tool]
            files[name] = b'{"fixture":true}'
        for name, data in files.items():
            (folder / name).write_bytes(data)
        artifacts = tuple(
            Artifact(n, len(d), hashlib.sha256(d).hexdigest()) for n, d in files.items()
        )
        failed = job.tool == self.failed_tool
        return JobResult(
            job_id,
            job.application_id,
            job.subject_id,
            "failed" if failed else "passed",
            1 if failed else 0,
            "Controlled executor fixture",
            False,
            artifacts,
            0.01,
            True,
            self.policy.tools[job.tool].image_id,
        )


def test_real_git_branch_and_exact_validation_linkage(prepared):
    request, policy = prepared
    runner = ControlledRunner(policy)
    report = remediate(
        request, runner, authorized_repositories={request.application_id: request.repository}
    )
    assert report["validated"] is True, report
    assert report["status"] == "passed"
    assert git(request.repository, "rev-parse", report["branch"]) == report["proposed_sha"]
    assert git(request.repository, "rev-parse", "HEAD") == request.base_sha
    assert "4.17.21" in git(
        request.repository, "show", f"{report['proposed_sha']}:package-lock.json"
    )
    assert {v["commit"] for v in report["attempts"][0]["validations"]} == {report["proposed_sha"]}
    assert (request.repository / "package.json").read_text().find("4.17.20") >= 0
    assert "4.17.21" in verify_artifact(report, request.repository)["package-lock.json"]
    with pytest.raises(ValueError, match="diff changed"):
        verify_artifact({**report, "diff_sha256": "0" * 64}, request.repository)
    with pytest.raises(ValueError, match="not validated"):
        verify_artifact({**report, "validated": False}, request.repository)


def test_failures_stop_and_are_durable(prepared):
    request, policy = prepared
    request = replace(request, versions=("4.17.21", "4.17.22", "4.17.23"), max_attempts=2)
    report = remediate(
        request,
        ControlledRunner(policy, "project_tests"),
        authorized_repositories={request.application_id: request.repository},
    )
    assert report["validated"] is False
    assert report["status"] == "failed"
    assert len(report["attempts"]) == 2
    assert report["stop_reason"] == "attempt_limit_or_candidates_exhausted"
    saved = json.loads(
        (policy.artifact_root / f"remediation-{report['id']}" / "remediation.json").read_text()
    )
    assert saved["attempts"][-1]["validations"][0]["status"] == "failed"


def test_missing_scanner_blocks_before_running(prepared):
    request, policy = prepared
    runner = ControlledRunner(replace(policy, tools={"npm_lockfile": policy.tools["npm_lockfile"]}))
    report = remediate(
        request, runner, authorized_repositories={request.application_id: request.repository}
    )
    assert report["status"] == "blocked"
    assert not runner.jobs and not report["validated"]
    assert "syft" in report["missing_tools"]


def test_rejects_unapproved_repository_and_revision(prepared):
    request, policy = prepared
    with pytest.raises(PermissionError):
        remediate(request, SimpleNamespace(policy=policy), authorized_repositories={})
    with pytest.raises(ValueError):
        replace(request, base_sha="HEAD")


def test_secret_file_is_rejected_without_executing(prepared):
    request, policy = prepared
    (request.repository / ".env").write_text("FIXTURE_ONLY=value")
    git(request.repository, "add", ".env")
    git(request.repository, "commit", "-m", "Forbidden fixture")
    request = replace(request, base_sha=git(request.repository, "rev-parse", "HEAD"))
    runner = ControlledRunner(policy)
    report = remediate(
        request, runner, authorized_repositories={request.application_id: request.repository}
    )
    assert report["status"] == "failed"
    assert not runner.jobs
