"""Syft invocation shape and CycloneDX parsing.

The real process is injected. A failing runner yields no SBOM document.
Pinned command: Syft 1.55.0, CycloneDX JSON 1.6, directory source, no enrich.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.parse import unquote

from alaira_warden.inventory.errors import InventoryError
from alaira_warden.inventory.models import Component, InventoryWarning

SYFT_VERSION = "1.55.0"
SYFT_SBOM_FORMAT = "cyclonedx-json@1.6"
SUPPORTED_CYCLONEDX = frozenset({"1.5", "1.6"})


class SyftCommandResult:
    def __init__(
        self,
        returncode: int,
        stdout: str = "",
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out


class SyftRunner(Protocol):
    def __call__(self, argv: list[str], *, timeout_seconds: float) -> SyftCommandResult: ...


@dataclass
class SyftCapture:
    version: str | None = None
    document_text: str | None = None
    document: dict | None = None
    error_code: str | None = None
    error_message: str | None = None
    commands: list[list[str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error_code is None and self.document is not None


def build_syft_version_command() -> list[str]:
    return ["syft", "version", "-o", "json"]


def build_syft_scan_command(checkout: Path) -> list[str]:
    directory = validate_scan_directory(checkout)
    rendered = str(directory)
    _reject_argument(rendered)
    return [
        "syft",
        "scan",
        f"dir:{rendered}",
        "--base-path",
        rendered,
        "-o",
        SYFT_SBOM_FORMAT,
    ]


def validate_scan_directory(checkout: Path, *, secrets: tuple[str, ...] = ()) -> Path:
    if not checkout.is_absolute():
        raise InventoryError("configuration", "Syft checkout path must be absolute")
    rendered = str(checkout)
    if any(mark in rendered for mark in ("\n", "\r", "\x00")):
        raise InventoryError("unsupported", "Syft checkout path is invalid")
    for secret in secrets:
        if secret and secret in rendered:
            raise InventoryError("configuration", "Syft checkout path is invalid")
    if ".." in checkout.parts:
        raise InventoryError("unsupported", "Syft checkout path is invalid")
    return checkout


def execute_syft(
    runner: SyftRunner,
    checkout: Path,
    *,
    timeout_seconds: float,
    secrets: tuple[str, ...] = (),
) -> SyftCapture:
    """Run the pinned version check and scan. Discard stdout when the runner fails."""
    if timeout_seconds <= 0:
        raise InventoryError("configuration", "Syft timeout must be positive")
    capture = SyftCapture()
    version_command = build_syft_version_command()
    capture.commands.append(version_command)
    version_result = _invoke(runner, version_command, timeout_seconds)
    if isinstance(version_result, str):
        capture.error_code = "syft_unavailable"
        capture.error_message = version_result
        return capture
    if version_result.timed_out:
        capture.error_code = "syft_failed"
        capture.error_message = "Syft version command timed out"
        return capture
    if version_result.returncode != 0:
        capture.error_code = "syft_unavailable"
        capture.error_message = "Syft version command failed"
        return capture
    try:
        version = _parse_version(version_result.stdout)
    except InventoryError:
        capture.error_code = "syft_invalid_sbom"
        capture.error_message = "Syft version output is not the pinned JSON contract"
        return capture
    if version != SYFT_VERSION:
        capture.error_code = "syft_version_unsupported"
        capture.error_message = "Syft version does not match the pinned release"
        return capture
    scan_command = build_syft_scan_command(checkout)
    for secret in secrets:
        if secret and any(secret in arg for arg in scan_command):
            capture.error_code = "syft_failed"
            capture.error_message = "Syft arguments were rejected"
            return capture
    capture.commands.append(scan_command)
    scan_result = _invoke(runner, scan_command, timeout_seconds)
    if isinstance(scan_result, str):
        capture.error_code = "syft_unavailable"
        capture.error_message = scan_result
        return capture
    if scan_result.timed_out or scan_result.returncode != 0:
        capture.error_code = "syft_failed"
        capture.error_message = "Syft scan failed"
        capture.version = version
        return capture
    try:
        document = parse_json_sbom(scan_result.stdout)
        parse_cyclonedx(document)
    except InventoryError:
        capture.error_code = "syft_invalid_sbom"
        capture.error_message = "Syft stdout was not a supported CycloneDX document"
        capture.version = version
        return capture
    capture.version = version
    capture.document_text = scan_result.stdout
    capture.document = document
    return capture


def parse_json_sbom(text: str) -> dict:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InventoryError("invalid_response", "SBOM is not valid JSON") from exc
    if not isinstance(value, dict):
        raise InventoryError("invalid_response", "SBOM must be a JSON object")
    return value


def parse_cyclonedx(document: dict) -> tuple[list[Component], list[InventoryWarning]]:
    if document.get("bomFormat") != "CycloneDX":
        raise InventoryError("unsupported", "Only CycloneDX JSON is supported")
    spec = str(document.get("specVersion") or "")
    if spec not in SUPPORTED_CYCLONEDX:
        raise InventoryError("unsupported", "CycloneDX specVersion must be 1.5 or 1.6")
    raw_components = document.get("components") or []
    if not isinstance(raw_components, list):
        raise InventoryError("invalid_response", "CycloneDX components must be a list")
    warnings: list[InventoryWarning] = []
    by_ref: dict[str, tuple[str, str | None]] = {}
    components: list[Component] = []
    for raw in raw_components:
        if not isinstance(raw, dict):
            warnings.append(
                InventoryWarning(
                    code="invalid_sbom_component",
                    message="A CycloneDX component was not an object",
                    blocks_completeness=True,
                )
            )
            continue
        if raw.get("components"):
            warnings.append(
                InventoryWarning(
                    code="nested_sbom_components_ignored",
                    message="Nested CycloneDX components were not expanded",
                    blocks_completeness=True,
                )
            )
        if raw.get("type") == "application":
            continue
        parsed = _npm_component(raw)
        if parsed is None:
            if raw.get("type") in {"library", "framework"}:
                warnings.append(
                    InventoryWarning(
                        code="sbom_component_without_purl",
                        message="Library component without an npm purl was not invented",
                        component=raw.get("name") if isinstance(raw.get("name"), str) else None,
                        blocks_completeness=True,
                    )
                )
            continue
        name, version, bom_ref = parsed
        if bom_ref:
            by_ref[bom_ref] = (name, version)
        components.append(
            Component(
                name=name,
                resolved_version=version,
                direct=False,
                dependency_paths=[],
                metadata={"origin": "syft", "sources": ["syft"], "bom_ref": bom_ref},
            )
        )
    paths = _dependency_paths(document, by_ref)
    for component in components:
        ref = component.metadata.get("bom_ref")
        found = paths.get(ref, []) if isinstance(ref, str) else []
        component.dependency_paths = found
        component.direct = any(len(path) == 1 for path in found)
        if version_blocks(component.resolved_version):
            warnings.append(
                InventoryWarning(
                    code="unresolved_component",
                    message="SBOM component has no concrete npm version",
                    component=component.name,
                    blocks_completeness=True,
                )
            )
    components.sort(
        key=lambda item: (
            item.name,
            item.resolved_version or "",
            str(item.metadata.get("bom_ref")),
        )
    )
    return components, warnings


def version_blocks(version: str | None) -> bool:
    return version is None


def _npm_component(raw: dict) -> tuple[str, str | None, str | None] | None:
    purl = raw.get("purl")
    if not isinstance(purl, str):
        return None
    name_version = _parse_npm_purl(purl)
    if name_version is None:
        return None
    name, version = name_version
    if version is None and isinstance(raw.get("version"), str):
        version = raw["version"]
    bom_ref = raw.get("bom-ref") if isinstance(raw.get("bom-ref"), str) else purl
    return name, version, bom_ref


def _parse_npm_purl(purl: str) -> tuple[str, str | None] | None:
    if not purl.startswith("pkg:npm/"):
        return None
    rest = purl[len("pkg:npm/") :].split("?", 1)[0].split("#", 1)[0]
    if not rest:
        return None
    if "@" in rest:
        name, version = rest.rsplit("@", 1)
        version = unquote(version) or None
    else:
        name, version = rest, None
    name = unquote(name)
    if not name:
        return None
    return name, version


def _dependency_paths(
    document: dict, by_ref: dict[str, tuple[str, str | None]]
) -> dict[str, list[list[str]]]:
    edges = document.get("dependencies") or []
    if not isinstance(edges, list):
        return {}
    graph: dict[str, list[str]] = {}
    for edge in edges:
        if not isinstance(edge, dict) or not isinstance(edge.get("ref"), str):
            continue
        depends = edge.get("dependsOn") or []
        if not isinstance(depends, list):
            continue
        graph[edge["ref"]] = [item for item in depends if isinstance(item, str)]
    roots = []
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        root_component = metadata.get("component")
        if isinstance(root_component, dict) and isinstance(root_component.get("bom-ref"), str):
            roots.append(root_component["bom-ref"])
    if not roots:
        referenced = {child for children in graph.values() for child in children}
        roots = [ref for ref in graph if ref not in referenced and ref not in by_ref]
    found: dict[str, list[list[str]]] = {}
    queue: list[tuple[str, list[str]]] = []
    for root in roots:
        for child in graph.get(root, []):
            if child in by_ref:
                queue.append((child, [_step(by_ref[child])]))
    while queue:
        ref, path = queue.pop(0)
        bucket = found.setdefault(ref, [])
        if path in bucket or len(bucket) >= 20 or len(path) > 25:
            continue
        bucket.append(path)
        for child in graph.get(ref, []):
            if child in by_ref:
                queue.append((child, [*path, _step(by_ref[child])]))
    return found


def _step(identity: tuple[str, str | None]) -> str:
    name, version = identity
    return f"{name}@{version if version else 'unresolved'}"


def _parse_version(stdout: str) -> str:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise InventoryError("invalid_response", "Syft version output is not JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("version"), str):
        raise InventoryError("invalid_response", "Syft version output has no version")
    return payload["version"]


def _invoke(runner: SyftRunner, argv: list[str], timeout_seconds: float) -> SyftCommandResult | str:
    try:
        return runner(argv, timeout_seconds=timeout_seconds)
    except TimeoutError:
        return "Syft runner timed out"
    except InventoryError:
        raise
    except Exception:
        return "Syft runner failed"


def _reject_argument(value: str) -> None:
    if any(mark in value for mark in ("\n", "\r", "\x00", ";", "|", "&")):
        raise InventoryError("unsupported", "Syft argument was rejected")
