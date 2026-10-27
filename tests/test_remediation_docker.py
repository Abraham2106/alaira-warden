"""Opt-in real npm update/tests in Docker, no scanner acceptance claims."""

import json
import os
import subprocess
from dataclasses import replace
from uuid import uuid4

import pytest

from alaira_warden.execution import DockerRunner, ExecutionPolicy, Job, Limits
from alaira_warden.remediation.tools import npm_tools

pytestmark = pytest.mark.skipif(
    os.getenv("WARDEN_RUN_REMEDIATION_DOCKER_TESTS") != "1",
    reason="Requires prebuilt alaira-warden-npm-tools image with public lodash cache",
)


def test_real_npm_lockfile_and_project_tests_offline(tmp_path):
    image = subprocess.check_output(
        ["docker", "image", "inspect", "alaira-warden-npm-tools", "--format", "{{.Id}}"],
        text=True,
    ).strip()
    source = tmp_path / "input"
    source.mkdir()
    manifest = {
        "name": "warden-offline-fixture",
        "version": "1.0.0",
        "private": True,
        "dependencies": {"lodash": "4.17.20"},
        "scripts": {"test": "node test.js"},
    }
    (source / "package.json").write_text(json.dumps(manifest))
    (source / "package-lock.json").write_text(
        json.dumps(
            {
                "name": manifest["name"],
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": True,
                "packages": {"": manifest},
            }
        )
    )
    (source / "test.js").write_text(
        "const assert=require('node:assert/strict');"
        "assert.equal(require('lodash/package.json').version,'4.17.21');\n"
    )
    app = uuid4()
    limits = replace(
        Limits(), memory_mb=512, temporary_mb=64, workspace_mb=64, timeout_seconds=90, files=512
    )
    runner = DockerRunner(
        ExecutionPolicy(source, tmp_path / "output", frozenset({app}), npm_tools(image), limits)
    )
    update = runner.run(Job(app, "fixture", source, "npm_lockfile", ("lodash", "4.17.21")))
    assert update.status == "passed", update
    assert update.cleanup_succeeded
    for name in ("package.json", "package-lock.json"):
        data = (runner.policy.artifact_root / update.job_id / "files" / name).read_bytes()
        (source / name).write_bytes(data)
    lock = json.loads((source / "package-lock.json").read_text())
    assert lock["packages"]["node_modules/lodash"]["version"] == "4.17.21"
    tests = runner.run(Job(app, "fixture", source, "project_tests"))
    assert tests.status == "passed", tests
    assert tests.cleanup_succeeded
