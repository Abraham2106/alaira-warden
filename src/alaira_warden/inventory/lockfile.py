"""npm package-lock.json versions 2 and 3.

Ranges in package.json are names only. A concrete version is taken from a
lockfile node that is not a git, file, or external link dependency.
"""

import json
from dataclasses import dataclass, field

from alaira_warden.inventory.errors import InventoryError
from alaira_warden.inventory.limits import InventoryLimits
from alaira_warden.inventory.models import Component, InventoryWarning
from alaira_warden.inventory.redact import sanitize_url

SUPPORTED_LOCKFILE_VERSIONS = (2, 3)
_RANGE_MARKS = ("^", "~", "*", " ", "<", ">", "|")


@dataclass
class LockNode:
    key: str
    name: str
    requested_name: str
    resolved_version: str | None
    origin: str
    dependencies: dict[str, str]
    scope_hint: str | None
    metadata: dict
    blocks: bool


@dataclass
class LockfileParse:
    lockfile_version: int | None
    components: list[Component]
    warnings: list[InventoryWarning]
    package_names: dict[str, str] = field(default_factory=dict)


def parse_json_object(text: str, *, label: str) -> dict:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InventoryError("invalid_response", f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise InventoryError("invalid_response", f"{label} must be a JSON object")
    return value


def parse_npm_project(
    lock_text: str | None,
    package_json_text: str | None = None,
    *,
    limits: InventoryLimits | None = None,
    secrets: tuple[str, ...] = (),
) -> LockfileParse:
    limits = limits or InventoryLimits()
    warnings: list[InventoryWarning] = []
    manifest_names: dict[str, str] = {}
    if package_json_text is not None:
        manifest_names, manifest_warnings = _manifest_names(package_json_text)
        warnings.extend(manifest_warnings)
    if lock_text is None:
        warnings.append(
            InventoryWarning(
                code="missing_lockfile",
                message="package-lock.json is absent; declared ranges were not treated as versions",
                path="package-lock.json",
                blocks_completeness=True,
            )
        )
        return LockfileParse(None, [], warnings, manifest_names)
    if len(lock_text.encode("utf-8")) > limits.max_file_bytes:
        raise InventoryError("budget_exceeded", "package-lock.json exceeds the size limit")
    try:
        document = parse_json_object(lock_text, label="package-lock.json")
    except InventoryError as exc:
        warnings.append(
            InventoryWarning(
                code="invalid_lockfile",
                message=str(exc),
                path="package-lock.json",
                blocks_completeness=True,
            )
        )
        return LockfileParse(None, [], warnings, manifest_names)
    version = document.get("lockfileVersion")
    if version not in SUPPORTED_LOCKFILE_VERSIONS:
        warnings.append(
            InventoryWarning(
                code="unsupported_lockfile",
                message="Only npm lockfileVersion 2 and 3 are supported",
                path="package-lock.json",
                blocks_completeness=True,
            )
        )
        return LockfileParse(None, [], warnings, manifest_names)
    packages = document.get("packages")
    if not isinstance(packages, dict):
        warnings.append(
            InventoryWarning(
                code="invalid_lockfile",
                message="package-lock.json has no packages object",
                path="package-lock.json",
                blocks_completeness=True,
            )
        )
        return LockfileParse(version, [], warnings, manifest_names)
    nodes, build_warnings = _nodes(packages, limits=limits, secrets=secrets)
    warnings.extend(build_warnings)
    root = packages.get("")
    _cross_check(manifest_names, root if isinstance(root, dict) else {}, warnings)
    components, walk_warnings = _walk(nodes, packages, limits)
    warnings.extend(walk_warnings)
    return LockfileParse(version, components, warnings, manifest_names)


def _manifest_names(text: str) -> tuple[dict[str, str], list[InventoryWarning]]:
    warnings: list[InventoryWarning] = []
    try:
        document = parse_json_object(text, label="package.json")
    except InventoryError as exc:
        return {}, [
            InventoryWarning(
                code="invalid_manifest",
                message=str(exc),
                path="package.json",
                blocks_completeness=True,
            )
        ]
    names: dict[str, str] = {}
    for field_name, scope in (
        ("dependencies", "production"),
        ("devDependencies", "development"),
        ("optionalDependencies", "optional"),
    ):
        raw = document.get(field_name) or {}
        if raw and not isinstance(raw, dict):
            warnings.append(
                InventoryWarning(
                    code="invalid_manifest",
                    message=f"package.json {field_name} is not an object",
                    path="package.json",
                    blocks_completeness=True,
                )
            )
            continue
        for name in raw:
            if isinstance(name, str) and name:
                if field_name == "optionalDependencies":
                    names[name] = "optional"
                else:
                    names.setdefault(name, scope)
    if document.get("overrides"):
        warnings.append(
            InventoryWarning(
                code="package_overrides_ignored",
                message="package.json overrides are not resolved; lockfile versions are used",
                path="package.json",
                blocks_completeness=False,
            )
        )
    return names, warnings


def _cross_check(
    manifest_names: dict[str, str], root: dict, warnings: list[InventoryWarning]
) -> None:
    if not manifest_names:
        return
    locked = set()
    for field_name in ("dependencies", "devDependencies", "optionalDependencies"):
        raw = root.get(field_name) or {}
        if isinstance(raw, dict):
            locked.update(name for name in raw if isinstance(name, str))
    for name in sorted(manifest_names):
        if name not in locked:
            warnings.append(
                InventoryWarning(
                    code="missing_locked_dependency",
                    message="Declared dependency has no lockfile entry; its range was not used",
                    path="package.json",
                    component=name,
                    blocks_completeness=True,
                )
            )


def _nodes(
    packages: dict, *, limits: InventoryLimits, secrets: tuple[str, ...]
) -> tuple[dict[str, LockNode], list[InventoryWarning]]:
    warnings: list[InventoryWarning] = []
    nodes: dict[str, LockNode] = {}
    for key, entry in packages.items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            warnings.append(
                InventoryWarning(
                    code="invalid_lockfile",
                    message="A lockfile package entry could not be read",
                    blocks_completeness=True,
                )
            )
            continue
        if "node_modules/" not in key:
            continue
        if len(nodes) >= limits.max_components:
            warnings.append(
                InventoryWarning(
                    code="component_budget_exceeded",
                    message="Component limit reached before the lockfile ended",
                    blocks_completeness=True,
                )
            )
            break
        node, node_warnings = _node(key, entry, packages, secrets)
        warnings.extend(node_warnings)
        if node is not None:
            nodes[key] = node
    return nodes, warnings


def _node(
    key: str, entry: dict, packages: dict, secrets: tuple[str, ...]
) -> tuple[LockNode | None, list[InventoryWarning]]:
    warnings: list[InventoryWarning] = []
    requested = _name_from_path(key)
    if requested is None:
        warnings.append(
            InventoryWarning(
                code="invalid_lockfile",
                message="A lockfile node path is not a package",
                path=key,
                blocks_completeness=True,
            )
        )
        return None, warnings
    if _is_workspace_link(entry, packages):
        warnings.append(
            InventoryWarning(
                code="local_workspace",
                message="Workspace link is part of the repository, not a registry component",
                path=key,
                component=requested,
                blocks_completeness=False,
            )
        )
        return None, warnings
    origin, version, extra, blocks = _origin(entry, secrets)
    declared = entry.get("name")
    name = declared if isinstance(declared, str) and declared else requested
    metadata = {"lock_path": key, "origin": origin, "sources": ["lockfile"], **extra}
    if name != requested:
        metadata["alias"] = requested
    if entry.get("optional") is True:
        metadata["optional"] = True
    if entry.get("dev") is True:
        metadata["lock_dev"] = True
    dependencies = _dependency_map(entry)
    return (
        LockNode(
            key=key,
            name=name,
            requested_name=requested,
            resolved_version=version,
            origin=origin,
            dependencies=dependencies,
            scope_hint="optional" if entry.get("optional") is True else None,
            metadata=metadata,
            blocks=blocks,
        ),
        warnings,
    )


def _origin(entry: dict, secrets: tuple[str, ...]) -> tuple[str, str | None, dict, bool]:
    resolved = entry.get("resolved") if isinstance(entry.get("resolved"), str) else ""
    version = entry.get("version") if isinstance(entry.get("version"), str) else None
    try:
        safe_resolved = sanitize_url(resolved, secrets) if resolved else ""
    except ValueError:
        safe_resolved = ""
    extra: dict = {}
    if version and not _is_range(version):
        extra["lock_version"] = version
    if _is_git(resolved):
        extra["unresolved_reason"] = "git"
        return "git", None, extra, True
    if entry.get("link") is True or resolved.startswith("file:"):
        extra["unresolved_reason"] = "local"
        return "local", None, extra, True
    if version is None or _is_range(version):
        extra["unresolved_reason"] = "version_not_concrete"
        return "unknown", None, extra, True
    if safe_resolved:
        extra["resolved_url"] = safe_resolved
    elif isinstance(entry.get("integrity"), str):
        extra["resolved_url_absent"] = True
        extra["integrity"] = entry["integrity"]
    else:
        extra["unresolved_reason"] = "missing_resolved_url"
        return "unknown", None, extra, True
    return "registry", version, extra, False


def _is_range(version: str) -> bool:
    return any(mark in version for mark in _RANGE_MARKS) or version == ""


def _is_git(resolved: str) -> bool:
    return resolved.startswith(("git+", "git://", "git@", "github:"))


def _is_workspace_link(entry: dict, packages: dict) -> bool:
    if entry.get("link") is not True:
        return False
    resolved = entry.get("resolved") if isinstance(entry.get("resolved"), str) else ""
    target = resolved.removeprefix("file:")
    if target.startswith(("..", "/", ".")) or "\\" in target or ":" in target:
        return False
    return target in packages


def _name_from_path(key: str) -> str | None:
    tail = key.rsplit("node_modules/", 1)[-1]
    if not tail or tail == key and not key.startswith("node_modules/"):
        return None
    if tail.startswith("@") and tail.count("/") != 1:
        return None
    if "/" in tail and not tail.startswith("@"):
        return None
    return tail


def _dependency_map(entry: dict) -> dict[str, str]:
    found: dict[str, str] = {}
    raw = entry.get("dependencies") or {}
    if isinstance(raw, dict):
        for name, spec in raw.items():
            if isinstance(name, str) and isinstance(spec, str):
                found[name] = spec
    optional = entry.get("optionalDependencies") or {}
    if isinstance(optional, dict):
        for name, spec in optional.items():
            if isinstance(name, str) and isinstance(spec, str):
                found.setdefault(name, spec)
    return found


def _root_requirements(packages: dict) -> list[tuple[str, str, str]]:
    """Return (from_key, dependency_name, scope) for the root and workspaces."""
    requirements: list[tuple[str, str, str]] = []
    for key, entry in packages.items():
        if not isinstance(entry, dict):
            continue
        in_modules = "node_modules/" in key or str(key).startswith("node_modules")
        root_like = key == "" or not in_modules
        if not root_like:
            continue
        scopes = (
            ("dependencies", "production"),
            ("devDependencies", "development"),
            ("optionalDependencies", "optional"),
        )
        if key != "":
            scopes = (("dependencies", "production"), ("optionalDependencies", "optional"))
        for field_name, scope in scopes:
            raw = entry.get(field_name) or {}
            if not isinstance(raw, dict):
                continue
            for name in raw:
                if isinstance(name, str):
                    requirements.append((str(key), name, scope))
    return requirements


def _resolve(from_key: str, dep_name: str, nodes: dict[str, LockNode]) -> str | None:
    suffix = f"node_modules/{dep_name}"
    current = from_key
    seen: set[str] = set()
    while current not in seen:
        seen.add(current)
        candidate = suffix if current == "" else f"{current}/{suffix}"
        if candidate in nodes:
            return candidate
        if current == "":
            return None
        if current.startswith("node_modules/") or "/node_modules/" in current:
            marker = "/node_modules/"
            current = current.rsplit(marker, 1)[0] if marker in current else ""
            continue
        if suffix in nodes:
            return suffix
        return None
    return None


def _label(node: LockNode) -> str:
    version = node.resolved_version if node.resolved_version is not None else "unresolved"
    return f"{node.name}@{version}"


def _walk(
    nodes: dict[str, LockNode], packages: dict, limits: InventoryLimits
) -> tuple[list[Component], list[InventoryWarning]]:
    warnings: list[InventoryWarning] = []
    paths: dict[str, list[list[str]]] = {key: [] for key in nodes}
    scopes: dict[str, str] = {}
    queue: list[tuple[str, list[str]]] = []
    for from_key, dep_name, scope in _root_requirements(packages):
        resolved = _resolve(from_key, dep_name, nodes)
        if resolved is None:
            if scope == "optional":
                warnings.append(
                    InventoryWarning(
                        code="optional_absent",
                        message="Optional dependency is not in the lockfile and was not invented",
                        component=dep_name,
                        blocks_completeness=False,
                    )
                )
            else:
                warnings.append(
                    InventoryWarning(
                        code="missing_locked_dependency",
                        message="Dependency declaration did not resolve inside the lockfile",
                        component=dep_name,
                        blocks_completeness=True,
                    )
                )
            continue
        queue.append((resolved, [_label(nodes[resolved])]))
        scopes.setdefault(resolved, scope)
    while queue:
        key, path = queue.pop(0)
        if len(path) > limits.max_dependency_depth:
            warnings.append(
                InventoryWarning(
                    code="dependency_depth_exceeded",
                    message="Dependency walk stopped at the configured depth",
                    path=key,
                    blocks_completeness=True,
                )
            )
            continue
        bucket = paths[key]
        if path in bucket:
            continue
        if len(bucket) >= limits.max_paths_per_component:
            warnings.append(
                InventoryWarning(
                    code="dependency_path_budget_exceeded",
                    message="Additional dependency paths were omitted",
                    path=key,
                    blocks_completeness=True,
                )
            )
            continue
        bucket.append(path)
        for child_name in nodes[key].dependencies:
            child = _resolve(key, child_name, nodes)
            if child is None:
                warnings.append(
                    InventoryWarning(
                        code="missing_locked_dependency",
                        message="A locked dependency did not resolve to a package node",
                        path=key,
                        component=child_name,
                        blocks_completeness=True,
                    )
                )
                continue
            queue.append((child, [*path, _label(nodes[child])]))
    components: list[Component] = []
    for key, node in nodes.items():
        node_paths = paths[key]
        if not node_paths:
            warnings.append(
                InventoryWarning(
                    code="orphan_lock_node",
                    message="Lockfile package is not reachable from the root or a workspace",
                    path=key,
                    component=node.name,
                    blocks_completeness=True,
                )
            )
        if node.blocks:
            warnings.append(
                InventoryWarning(
                    code=(
                        f"{node.origin}_dependency"
                        if node.origin in {"git", "local"}
                        else "unresolved_component"
                    ),
                    message="Component version was not resolved from a registry lock entry",
                    path=key,
                    component=node.name,
                    blocks_completeness=True,
                )
            )
        scope = scopes.get(key, "transitive")
        direct = any(len(item) == 1 for item in node_paths)
        if not direct:
            scope = "transitive"
        metadata = dict(node.metadata)
        metadata["dependency_scope"] = scope
        components.append(
            Component(
                name=node.name,
                resolved_version=node.resolved_version,
                direct=direct,
                dependency_paths=node_paths,
                metadata=metadata,
            )
        )
    components.sort(
        key=lambda item: (
            item.name,
            item.resolved_version or "",
            item.metadata.get("lock_path", ""),
        )
    )
    return components, warnings
