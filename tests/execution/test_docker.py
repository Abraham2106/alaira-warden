"""Opt-in real Docker checks. No repository scripts, private inputs or network access."""

import json
import os
import subprocess
import threading
from dataclasses import replace
from uuid import uuid4

import pytest

from alaira_warden.execution import DockerRunner, ExecutionPolicy, Job, Limits, Tool

pytestmark = pytest.mark.skipif(
    os.environ.get("WARDEN_RUN_DOCKER_TESTS") != "1", reason="Real Docker tests are opt-in"
)


@pytest.fixture
def runner(tmp_path):
    image = subprocess.check_output(
        ["docker", "image", "inspect", "alaira-warden-api", "--format", "{{.Id}}"], text=True
    ).strip()
    source = tmp_path / "input"
    source.mkdir()
    (source / "fixture.txt").write_text("synthetic fixture", encoding="utf-8")
    application = uuid4()
    settings = ExecutionPolicy(
        input_root=source,
        artifact_root=tmp_path / "artifacts",
        allowed_applications=frozenset({application}),
        tools={"python": Tool(image, "/usr/local/bin/python", ("-I", "-B"))},
    )
    return DockerRunner(settings), application, source


def assert_removed(runner, result):
    assert result.cleanup_succeeded
    response = subprocess.run(
        [*runner.command, "inspect", f"warden-job-{result.job_id}"],
        capture_output=True,
        env=runner.environment,
    )
    assert response.returncode != 0


def test_real_isolation_input_and_artifacts(runner):
    executor, application, source = runner
    script = """
import os, pathlib, socket
assert os.getuid() == 10001
assert pathlib.Path('fixture.txt').read_text() == 'synthetic fixture'
assert not pathlib.Path('/var/run/docker.sock').exists()
assert not os.environ.get('WARDEN_API_TOKEN')
try:
    pathlib.Path('/forbidden-root-write').write_text('no')
except OSError:
    pass
else:
    raise AssertionError('Root filesystem is writable')
try:
    socket.create_connection(('1.1.1.1', 443), timeout=0.3)
except OSError:
    pass
else:
    raise AssertionError('Network is available')
pathlib.Path('artifacts/proof.json').write_text('{"isolated":true}')
print('isolated')
"""
    result = executor.run(Job(application, "synthetic-user", source, "python", ("-c", script)))
    assert result.status == "passed", result
    assert result.output.strip() == "isolated"
    artifact = executor.policy.artifact_root / result.job_id / "files" / "proof.json"
    assert json.loads(artifact.read_text()) == {"isolated": True}
    assert_removed(executor, result)


@pytest.mark.parametrize("scenario", ["failure", "timeout", "output", "cancel", "symlink"])
def test_real_failures_are_bounded_and_cleaned(runner, scenario):
    executor, application, source = runner
    cancel = threading.Event()
    timer = None
    script = "raise SystemExit(7)"
    expected = "failed"
    if scenario == "timeout":
        executor.policy = replace(executor.policy, limits=replace(Limits(), timeout_seconds=5))
        script, expected = "import time; time.sleep(30)", "timed_out"
    if scenario == "output":
        executor.policy = replace(executor.policy, limits=replace(Limits(), output_bytes=1024))
        script, expected = "print('x' * 1000000)", "output_limit"
    if scenario == "cancel":
        timer = threading.Timer(3, cancel.set)
        timer.start()
        script, expected = "import time; time.sleep(30)", "cancelled"
    if scenario == "symlink":
        script = "import os; os.symlink('/etc/passwd', 'artifacts/leak')"
        expected = "artifact_limit"
    try:
        result = executor.run(
            Job(application, "synthetic-user", source, "python", ("-c", script)), cancel
        )
        assert result.status == expected, result
        assert len(result.output.encode()) <= executor.policy.limits.output_bytes
        assert_removed(executor, result)
    finally:
        if timer:
            timer.cancel()
