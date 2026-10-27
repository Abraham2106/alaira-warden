import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from alaira_warden.inventory import (
    AuthorizedApplication,
    InventoryError,
    InventoryLimits,
    execute_syft,
    materialize_files,
    read_github_repository,
    snapshot_from_github,
    snapshot_from_manifests,
)
from alaira_warden.inventory.syft import SYFT_VERSION, SyftCommandResult, build_syft_scan_command

FIXTURES = Path(__file__).parent / "fixtures"
OBSERVED = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
SHA = "0123456789abcdef0123456789abcdef01234567"
TOKEN = "ghp_testtokenvalue1234567890"


def application() -> AuthorizedApplication:
    return AuthorizedApplication(
        application_id=uuid4(),
        repository="octo/registry-app",
        environments=("production",),
        owner="ada",
        criticality="high",
    )


class Runner:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, argv, *, timeout_seconds):
        self.calls.append((argv, timeout_seconds))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class Transport:
    def __init__(self, routes, clock_jumps=None):
        self.routes = routes
        self.calls = []
        self.clock_jumps = list(clock_jumps or [])

    def request(self, method, url, headers, timeout_seconds):
        self.calls.append((method, url, dict(headers), timeout_seconds))
        if TOKEN in url:
            raise AssertionError("token leaked into URL")
        response = self.routes[url]
        if isinstance(response, Exception):
            raise response
        return response


class Response:
    def __init__(self, status, body, headers=None):
        self.status = status
        self.body = body if isinstance(body, bytes) else body.encode("utf-8")
        self.headers = headers or {}


def registry_files() -> dict[str, str]:
    root = FIXTURES / "registry_app"
    return {
        "package.json": (root / "package.json").read_text(encoding="utf-8"),
        "package-lock.json": (root / "package-lock.json").read_text(encoding="utf-8"),
    }


def tree_for(files: dict[str, str]) -> dict:
    return {
        "truncated": False,
        "tree": [
            {
                "path": path,
                "mode": "100644",
                "type": "blob",
                "sha": f"blob{index}",
                "size": len(text.encode("utf-8")),
            }
            for index, (path, text) in enumerate(files.items())
        ],
    }


def test_failed_or_missing_syft_runner_does_not_invent_an_sbom(tmp_path: Path):
    files = registry_files()
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    failing = Runner(
        [
            SyftCommandResult(0, json.dumps({"version": SYFT_VERSION})),
            SyftCommandResult(
                1,
                stdout=json.dumps(
                    {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
                ),
                stderr=TOKEN,
            ),
        ]
    )
    snapshot = snapshot_from_github(
        application=application(),
        ref=SHA,
        transport=_github(files),
        allowed_repositories={"octo/registry-app"},
        token=TOKEN,
        observed_at=OBSERVED,
        syft_runner=failing,
        checkout_dir=checkout,
    )
    assert snapshot.completeness == "partial"
    assert snapshot.tool_name == "npm-lockfile"
    assert snapshot.metadata.get("sbom_sha256") is None
    assert "ghost" not in {item.name for item in snapshot.components}
    assert TOKEN not in snapshot.model_dump_json()
    assert all(TOKEN not in " ".join(argv) for argv, _timeout in failing.calls)
    assert len(failing.calls) == 2

    absent = Runner([FileNotFoundError(TOKEN)])
    capture = execute_syft(absent, tmp_path, timeout_seconds=5)
    assert capture.document is None
    assert capture.document_text is None
    assert capture.ok is False
    assert capture.error_message == "Syft runner failed"
    assert TOKEN not in (capture.error_message or "")


def test_syft_version_mismatch_does_not_scan():
    checkout = Path("C:/tmp/warden-checkout") if os.name == "nt" else Path("/tmp/warden-checkout")
    runner = Runner([SyftCommandResult(0, json.dumps({"version": "0.0.1"}))])
    capture = execute_syft(runner, checkout, timeout_seconds=5)
    assert capture.document is None
    assert capture.error_code == "syft_version_unsupported"
    assert len(runner.calls) == 1
    command = build_syft_scan_command(checkout)
    assert command[0:3] == ["syft", "scan", f"dir:{checkout}"]
    assert "cyclonedx-json@1.6" in command
    assert "--enrich" not in command
    assert all(";" not in arg and "&&" not in arg for arg in command)


def test_github_resolves_mutable_ref_and_rejects_unauthorized_repo():
    files = registry_files()
    transport = _github(files, ref="main")
    read = read_github_repository(
        repository="octo/registry-app",
        ref="main",
        transport=transport,
        allowed_repositories={"octo/registry-app"},
        token=TOKEN,
        limits=InventoryLimits(timeout_seconds=5),
    )
    assert read.commit_sha == SHA
    assert read.requested_ref == "main"
    assert set(read.files) == {"package.json", "package-lock.json"}
    assert all(call[0] == "GET" for call in transport.calls)
    assert all(TOKEN not in call[1] for call in transport.calls)
    assert all(call[2]["Authorization"] == f"Bearer {TOKEN}" for call in transport.calls)
    with pytest.raises(InventoryError) as denied:
        read_github_repository(
            repository="octo/other",
            ref="main",
            transport=transport,
            allowed_repositories={"octo/registry-app"},
            token=TOKEN,
        )
    assert denied.value.category == "forbidden"
    assert len(transport.calls) == 4


def test_github_timeout_symlink_and_secret_errors_do_not_leak_the_token():
    files = registry_files()
    transport = _github(files)
    jumps = iter([0, 0, 0, 100])

    def clock():
        return next(jumps)

    with pytest.raises(InventoryError) as timed:
        read_github_repository(
            repository="octo/registry-app",
            ref=SHA,
            transport=transport,
            allowed_repositories={"octo/registry-app"},
            token=TOKEN,
            limits=InventoryLimits(timeout_seconds=5),
            clock=clock,
        )
    assert timed.value.category == "timeout"
    assert len(transport.calls) == 2

    leaked = Transport(
        {
            _commit_url(SHA): Response(500, TOKEN),
        }
    )
    with pytest.raises(InventoryError) as failed:
        read_github_repository(
            repository="octo/registry-app",
            ref=SHA,
            transport=leaked,
            allowed_repositories={"octo/registry-app"},
            token=TOKEN,
        )
    assert TOKEN not in str(failed.value)

    symlink = Transport(
        {
            _commit_url(SHA): Response(200, json.dumps({"sha": SHA})),
            _tree_url(SHA): Response(
                200,
                json.dumps(
                    {
                        "truncated": False,
                        "tree": [
                            {
                                "path": "package-lock.json",
                                "mode": "120000",
                                "type": "blob",
                                "sha": "linksha",
                                "size": 4,
                            }
                        ],
                    }
                ),
            ),
        }
    )
    read = read_github_repository(
        repository="octo/registry-app",
        ref=SHA,
        transport=symlink,
        allowed_repositories={"octo/registry-app"},
        token="",
    )
    assert read.files == {}
    assert any(warning.code == "symlink_rejected" for warning in read.warnings)
    assert all("blobs/linksha" not in call[1] for call in symlink.calls)


def test_materialize_rejects_escape_and_symlink(tmp_path: Path):
    root = tmp_path / "checkout"
    root.mkdir()
    limits = InventoryLimits(max_file_bytes=8)
    materialize_files(root, {"package.json": b"{}"}, limits=InventoryLimits())
    assert (root / "package.json").read_bytes() == b"{}"
    escapes = ("../outside.json", "/etc/passwd", "C:/Windows/package.json", "pkg/../../x.json")
    for relative in escapes:
        with pytest.raises(InventoryError):
            materialize_files(root, {relative: b"{}"}, limits=InventoryLimits())
    with pytest.raises(InventoryError) as too_big:
        materialize_files(root, {"package.json": b"0123456789"}, limits=limits)
    assert too_big.value.category == "budget_exceeded"
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "linked.json"
    try:
        os.symlink(outside / "secret.txt", link)
    except OSError:
        pytest.skip("symlink creation is not permitted")
    with pytest.raises(InventoryError) as escaped:
        materialize_files(root, {"linked.json": b"{}"})
    assert escaped.value.category == "unsupported"
    assert not (outside / "secret.txt").exists()


def test_snapshot_identity_is_the_commit_not_the_branch(tmp_path: Path):
    files = registry_files()
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    snapshot = snapshot_from_github(
        application=application(),
        ref="main",
        transport=_github(files, ref="main"),
        allowed_repositories={"octo/registry-app"},
        token=TOKEN,
        observed_at=OBSERVED,
        checkout_dir=checkout,
    )
    assert snapshot.commit_sha == SHA
    assert snapshot.metadata["requested_ref"] == "main"
    assert snapshot.completeness == "complete"
    second = snapshot_from_manifests(
        application=application(),
        commit_sha="b" * 40,
        observed_at=OBSERVED,
        package_json_text=files["package.json"],
        package_lock_text=files["package-lock.json"],
    )
    assert snapshot.commit_sha != second.commit_sha


def _github(files: dict[str, str], ref: str = SHA) -> Transport:
    routes = {
        _commit_url(ref): Response(200, json.dumps({"sha": SHA})),
        _tree_url(SHA): Response(200, json.dumps(tree_for(files))),
    }
    for index, (_path, text) in enumerate(files.items()):
        routes[_blob_url(f"blob{index}")] = Response(200, text)
    return Transport(routes)


def _commit_url(ref: str) -> str:
    return f"https://api.github.com/repos/octo/registry-app/commits/{ref}"


def _tree_url(sha: str) -> str:
    return f"https://api.github.com/repos/octo/registry-app/git/trees/{sha}?recursive=1"


def _blob_url(blob: str) -> str:
    return f"https://api.github.com/repos/octo/registry-app/git/blobs/{blob}"
