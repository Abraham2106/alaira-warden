import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from alaira_warden.inventory import (
    AuthorizedApplication,
    assess_snapshot,
    parse_npm_project,
    retain_snapshots,
    snapshot_from_manifests,
)
from alaira_warden.inventory.syft import SyftCapture, parse_json_sbom

FIXTURES = Path(__file__).parent / "fixtures"
OBSERVED = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
SHA_A = "a" * 40
SHA_B = "b" * 40


def application() -> AuthorizedApplication:
    return AuthorizedApplication(
        application_id=uuid4(),
        repository="octo/registry-app",
        environments=("production", "staging"),
        owner="ada",
        criticality="high",
    )


def registry_texts() -> tuple[str, str]:
    root = FIXTURES / "registry_app"
    return (
        (root / "package.json").read_text(encoding="utf-8"),
        (root / "package-lock.json").read_text(encoding="utf-8"),
    )


def component(snapshot, name, version):
    found = [
        item
        for item in snapshot.components
        if item.name == name and item.resolved_version == version
    ]
    assert len(found) == 1
    return found[0]


def test_registry_lockfile_keeps_direct_transitive_alias_and_two_versions():
    package_json, lock = registry_texts()
    snapshot = snapshot_from_manifests(
        application=application(),
        commit_sha=SHA_A,
        observed_at=OBSERVED,
        package_json_text=package_json,
        package_lock_text=lock,
    )
    assert snapshot.completeness == "complete"
    assert snapshot.tool_name == "npm-lockfile"
    assert snapshot.tool_version == "3"
    assert snapshot.commit_sha == SHA_A
    left = component(snapshot, "left-pad", "1.3.0")
    assert left.direct is True
    assert left.dependency_paths == [["left-pad@1.3.0"]]
    lodash = component(snapshot, "lodash", "4.17.21")
    assert lodash.direct is True
    assert lodash.metadata["alias"] == "alias-lodash"
    assert lodash.resolved_version != "^4.17.0"
    express = component(snapshot, "express", "4.18.2")
    assert express.direct is True
    qs_old = component(snapshot, "qs", "6.5.3")
    qs_new = component(snapshot, "qs", "6.11.0")
    assert qs_old.direct is False
    assert qs_new.direct is False
    assert qs_old.dependency_paths == [["express@4.18.2", "qs@6.5.3"]]
    assert qs_new.dependency_paths == [["express@4.18.2", "body-parser@1.20.1", "qs@6.11.0"]]
    assert component(snapshot, "dev-tool", "2.0.0").metadata["dependency_scope"] == "development"
    assert component(snapshot, "optional-native", "1.2.3").metadata["optional"] is True
    assert all(
        item.resolved_version is None or item.resolved_version[:1] not in "^~*<>"
        for item in snapshot.components
    )


def test_missing_invalid_and_unsupported_lockfiles_do_not_invent_versions():
    package_json = (FIXTURES / "ranges_only.json").read_text(encoding="utf-8")
    missing = snapshot_from_manifests(
        application=application(),
        commit_sha=SHA_A,
        observed_at=OBSERVED,
        package_json_text=package_json,
        package_lock_text=None,
    )
    assert missing.completeness == "failed"
    assert missing.components == []
    assert any(warning.code == "missing_lockfile" for warning in missing.warnings)
    assert "99.0.0" not in missing.model_dump_json()

    invalid = snapshot_from_manifests(
        application=application(),
        commit_sha=SHA_A,
        observed_at=OBSERVED,
        package_json_text=None,
        package_lock_text=(FIXTURES / "invalid.json").read_text(encoding="utf-8"),
    )
    assert invalid.completeness == "failed"
    assert invalid.components == []
    assert any(warning.code == "invalid_lockfile" for warning in invalid.warnings)

    legacy = parse_npm_project((FIXTURES / "lock_v1.json").read_text(encoding="utf-8"))
    assert legacy.components == []
    assert any(warning.code == "unsupported_lockfile" for warning in legacy.warnings)
    assert "1.3.0" not in json.dumps([item.model_dump() for item in legacy.components])


def test_git_and_local_dependencies_are_unresolved_limitations():
    lock = (FIXTURES / "limited_app" / "package-lock.json").read_text(encoding="utf-8")
    parsed = parse_npm_project(lock, secrets=("ghp_lockfilesecret",))
    snapshot = snapshot_from_manifests(
        application=application(),
        commit_sha=SHA_A,
        observed_at=OBSERVED,
        package_json_text=None,
        package_lock_text=lock,
        secrets=("ghp_lockfilesecret",),
    )
    assert snapshot.completeness == "partial"
    git_tool = next(item for item in parsed.components if item.name == "git-tool")
    local = next(item for item in parsed.components if item.name == "local-lib")
    assert git_tool.resolved_version is None
    assert git_tool.metadata["origin"] == "git"
    assert git_tool.metadata["lock_version"] == "0.3.1"
    assert local.resolved_version is None
    assert local.metadata["origin"] == "local"
    dumped = snapshot.model_dump_json()
    assert "ghp_lockfilesecret" not in dumped
    assert "user:ghp" not in dumped


def test_workspace_link_does_not_block_a_resolved_registry_dependency():
    lock = (FIXTURES / "workspace_app" / "package-lock.json").read_text(encoding="utf-8")
    snapshot = snapshot_from_manifests(
        application=application(),
        commit_sha=SHA_A,
        observed_at=OBSERVED,
        package_json_text=None,
        package_lock_text=lock,
    )
    assert snapshot.completeness == "complete"
    assert [item.name for item in snapshot.components] == ["left-pad"]
    assert any(warning.code == "local_workspace" for warning in snapshot.warnings)


def test_two_commits_are_retained_and_expiry_does_not_rewrite_completeness():
    package_json, lock = registry_texts()
    first = snapshot_from_manifests(
        application=application(),
        commit_sha=SHA_A,
        observed_at=OBSERVED,
        package_json_text=package_json,
        package_lock_text=lock,
    )
    second = snapshot_from_manifests(
        application=application(),
        commit_sha=SHA_B,
        observed_at=OBSERVED,
        package_json_text=package_json,
        package_lock_text=lock,
    )
    history = retain_snapshots(retain_snapshots([], first), second)
    assert [item.commit_sha for item in history] == [SHA_A, SHA_B]
    stale = assess_snapshot(first, now=OBSERVED + timedelta(days=8), max_age=timedelta(days=7))
    assert first.completeness == "complete"
    assert stale.expired is True
    assert stale.limits_conclusion is True
    assert stale.completeness == "complete"
    assert any(warning.code == "inventory_expired" for warning in stale.warnings)
    fresh = assess_snapshot(first, now=OBSERVED + timedelta(days=6), max_age=timedelta(days=7))
    assert fresh.expired is False
    assert fresh.limits_conclusion is False


def test_syft_discrepancy_keeps_both_sides_and_recovers_lockfile_paths():
    package_json, lock = registry_texts()
    document = parse_json_sbom((FIXTURES / "syft_discrepancy.cdx.json").read_text(encoding="utf-8"))
    capture = SyftCapture(version="1.55.0", document_text="{}", document=document)
    snapshot = snapshot_from_manifests(
        application=application(),
        commit_sha=SHA_A,
        observed_at=OBSERVED,
        package_json_text=package_json,
        package_lock_text=lock,
        syft=capture,
    )
    assert snapshot.completeness == "partial"
    assert snapshot.tool_name == "syft"
    assert snapshot.tool_version == "1.55.0"
    assert component(snapshot, "lodash", "4.17.21").metadata["sources"] == ["lockfile"]
    assert component(snapshot, "lodash", "4.17.20").metadata["sources"] == ["syft"]
    assert component(snapshot, "ghost", "9.9.9").name == "ghost"
    recovered = component(snapshot, "qs", "6.11.0")
    assert recovered.dependency_paths == [["express@4.18.2", "body-parser@1.20.1", "qs@6.11.0"]]
    assert recovered.metadata["paths_recovered_from_lockfile"] is True
    codes = {warning.code for warning in snapshot.warnings}
    assert {"version_discrepancy", "sbom_only", "lockfile_only"} <= codes
