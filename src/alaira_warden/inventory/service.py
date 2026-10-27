"""Build an inventory snapshot from manifests and an optional Syft capture."""

import hashlib
import tempfile
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from alaira_warden.inventory.errors import InventoryError
from alaira_warden.inventory.github_read import GitHubTransport, read_github_repository
from alaira_warden.inventory.limits import InventoryLimits
from alaira_warden.inventory.lockfile import parse_npm_project
from alaira_warden.inventory.materialize import materialize_files
from alaira_warden.inventory.models import (
    AuthorizedApplication,
    InventorySnapshot,
    InventoryWarning,
)
from alaira_warden.inventory.paths import normalize_repo_path
from alaira_warden.inventory.quality import QUALITY_POLICY, classify_completeness
from alaira_warden.inventory.reconcile import reconcile
from alaira_warden.inventory.syft import SyftCapture, SyftRunner, execute_syft, parse_cyclonedx


def registration_gaps(application: AuthorizedApplication) -> list[str]:
    gaps: list[str] = []
    if not application.owner:
        gaps.append("owner")
    if application.criticality is None:
        gaps.append("criticality")
    if not application.environments:
        gaps.append("environments")
    return gaps


def snapshot_from_manifests(
    *,
    application: AuthorizedApplication,
    commit_sha: str,
    observed_at: datetime,
    package_json_text: str | None,
    package_lock_text: str | None,
    syft: SyftCapture | None = None,
    extra_warnings: list[InventoryWarning] | None = None,
    requested_ref: str | None = None,
    artifact_path: str | None = None,
    limits: InventoryLimits | None = None,
    secrets: tuple[str, ...] = (),
) -> InventorySnapshot:
    limits = limits or InventoryLimits()
    warnings = list(extra_warnings or [])
    parsed = parse_npm_project(
        package_lock_text,
        package_json_text,
        limits=limits,
        secrets=secrets,
    )
    warnings.extend(parsed.warnings)
    syft_requested = syft is not None
    syft_ok = bool(syft and syft.ok)
    syft_components: list = []
    if syft is not None and not syft.ok:
        warnings.append(
            InventoryWarning(
                code=syft.error_code or "syft_failed",
                message=syft.error_message or "Syft did not produce an SBOM",
                blocks_completeness=True,
            )
        )
    elif syft is not None and syft.document is not None:
        try:
            syft_components, syft_warnings = parse_cyclonedx(syft.document)
        except InventoryError as exc:
            syft_ok = False
            warnings.append(
                InventoryWarning(
                    code="syft_invalid_sbom",
                    message=str(exc),
                    blocks_completeness=True,
                )
            )
        else:
            warnings.extend(syft_warnings)
    if parsed.components and syft_ok:
        components, reconcile_warnings = reconcile(parsed.components, syft_components)
        warnings.extend(reconcile_warnings)
    elif parsed.components:
        components = parsed.components
    elif syft_ok:
        components = syft_components
    else:
        components = []
    completeness = classify_completeness(
        components_present=bool(components),
        warnings=warnings,
        syft_requested=syft_requested,
        syft_ok=syft_ok,
    )
    if syft_ok and syft is not None and syft.version:
        tool_name = "syft"
        tool_version = syft.version
    else:
        tool_name = "npm-lockfile"
        tool_version = str(parsed.lockfile_version) if parsed.lockfile_version else "unavailable"
    metadata: dict = {"quality_policy": QUALITY_POLICY}
    if parsed.lockfile_version is not None:
        metadata["lockfile_version"] = parsed.lockfile_version
    if package_lock_text is not None:
        metadata["lockfile_sha256"] = _sha256(package_lock_text)
    if requested_ref:
        metadata["requested_ref"] = requested_ref
    artifact_hash = None
    if syft_ok and syft is not None and syft.document_text is not None:
        artifact_hash = _sha256(syft.document_text)
        metadata["sbom_format"] = "CycloneDX JSON 1.5/1.6"
        metadata["sbom_sha256"] = artifact_hash
        metadata["syft_version"] = syft.version
    elif package_lock_text is not None:
        artifact_hash = metadata.get("lockfile_sha256")
    return InventorySnapshot(
        application_id=application.application_id,
        repository=application.repository,
        commit_sha=commit_sha,
        observed_at=observed_at,
        tool_name=tool_name,
        tool_version=tool_version,
        completeness=completeness,
        components=components,
        warnings=warnings,
        artifact_path=_artifact_key(artifact_path),
        artifact_hash=artifact_hash,
        metadata=metadata,
    )


def snapshot_from_github(
    *,
    application: AuthorizedApplication,
    ref: str,
    transport: GitHubTransport,
    allowed_repositories: set[str] | frozenset[str],
    token: str,
    observed_at: datetime,
    limits: InventoryLimits | None = None,
    syft_runner: SyftRunner | None = None,
    checkout_dir: Path | None = None,
    clock: Callable[[], float] | None = None,
    api_base: str = "https://api.github.com",
) -> InventorySnapshot:
    limits = limits or InventoryLimits()
    read = read_github_repository(
        repository=application.repository,
        ref=ref,
        transport=transport,
        allowed_repositories=allowed_repositories,
        token=token,
        limits=limits,
        api_base=api_base,
        clock=clock or time.monotonic,
    )
    warnings = list(read.warnings)
    for path in read.files:
        if path != "package.json" and path.endswith("package.json"):
            warnings.append(
                InventoryWarning(
                    code="nested_manifest_ignored",
                    message="Nested package.json was not used as a version source",
                    path=path,
                    blocks_completeness=False,
                )
            )
    syft = None
    if syft_runner is not None:
        syft = _run_syft(syft_runner, read.files, checkout_dir, limits, (token,) if token else ())
    return snapshot_from_manifests(
        application=application,
        commit_sha=read.commit_sha,
        observed_at=observed_at,
        package_json_text=read.files.get("package.json"),
        package_lock_text=read.files.get("package-lock.json"),
        syft=syft,
        extra_warnings=warnings,
        requested_ref=read.requested_ref,
        limits=limits,
        secrets=(token,) if token else (),
    )


def _run_syft(
    runner: SyftRunner,
    files: dict[str, str],
    checkout_dir: Path | None,
    limits: InventoryLimits,
    secrets: tuple[str, ...],
) -> SyftCapture:
    payloads = {path: text.encode("utf-8") for path, text in files.items()}
    if checkout_dir is None:
        with tempfile.TemporaryDirectory(prefix="warden-inventory-") as temporary:
            root = Path(temporary)
            materialize_files(root, payloads, limits=limits)
            return execute_syft(
                runner, root, timeout_seconds=limits.timeout_seconds, secrets=secrets
            )
    materialize_files(checkout_dir, payloads, limits=limits)
    return execute_syft(
        runner, checkout_dir, timeout_seconds=limits.timeout_seconds, secrets=secrets
    )


def _artifact_key(artifact_path: str | None) -> str | None:
    if artifact_path is None:
        return None
    return normalize_repo_path(artifact_path)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
