from uuid import uuid4

import pytest

from alaira_warden.execution import DockerRunner, ExecutionPolicy, Job, Limits, Tool

IMAGE = "sha256:" + "a" * 64


def policy(tmp_path):
    application = uuid4()
    source = tmp_path / "input"
    source.mkdir()
    return ExecutionPolicy(
        input_root=source,
        artifact_root=tmp_path / "results",
        allowed_applications=frozenset({application}),
        tools={"test": Tool(IMAGE, "/usr/local/bin/python", ("-I", "-B"))},
    ), application


def test_mutable_images_remote_daemons_and_unbounded_limits_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        Tool("python:latest", "/usr/local/bin/python")
    with pytest.raises(ValueError):
        ExecutionPolicy(tmp_path, tmp_path, frozenset(), {}, docker_host="tcp://example.com:2375")
    with pytest.raises(ValueError):
        Limits(timeout_seconds=float("inf"))
    with pytest.raises(ValueError):
        ExecutionPolicy(tmp_path, tmp_path / "results", frozenset(), {})


def test_container_arguments_have_all_required_boundaries(tmp_path):
    settings, _ = policy(tmp_path)
    runner = DockerRunner(settings)
    arguments = runner.create_arguments("warden-job-test", settings.tools["test"])
    for required in (
        "--pull=never",
        "--network=none",
        "--ipc=none",
        "--read-only",
        "--user=10001:10001",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--memory=128m",
        "--memory-swap=128m",
        "--pids-limit=64",
        "--log-driver=none",
    ):
        assert required in arguments
    assert not any(arg.startswith(("--volume", "--mount", "--privileged")) for arg in arguments)


def test_wrong_application_or_unknown_tool_is_denied_before_docker(tmp_path, monkeypatch):
    settings, application = policy(tmp_path)
    runner = DockerRunner(settings)

    def never_called(*args, **kwargs):
        pytest.fail("Denied request reached Docker")

    monkeypatch.setattr(runner, "_control", never_called)
    for job in (
        Job(uuid4(), "subject", tmp_path, "test"),
        Job(application, "subject", tmp_path, "unknown"),
        Job(application, "", tmp_path, "test"),
    ):
        with pytest.raises(PermissionError):
            runner.run(job)


def test_host_secrets_and_remote_context_are_not_forwarded(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_API_TOKEN", "must-never-arrive")
    monkeypatch.setenv("DOCKER_HOST", "tcp://remote:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "remote")
    settings, _ = policy(tmp_path)
    runner = DockerRunner(settings)
    assert not {"WARDEN_API_TOKEN", "DOCKER_HOST", "DOCKER_CONTEXT"} & runner.environment.keys()
