"""Keep both lockfile and SBOM facts when they disagree."""

from alaira_warden.inventory.models import Component, InventoryWarning


def reconcile(
    lock_components: list[Component], sbom_components: list[Component]
) -> tuple[list[Component], list[InventoryWarning]]:
    warnings: list[InventoryWarning] = []
    lock_index: dict[tuple[str, str], list[Component]] = {}
    lock_names: dict[str, set[str]] = {}
    for component in lock_components:
        if component.resolved_version is None:
            continue
        lock_index.setdefault((component.name, component.resolved_version), []).append(component)
        lock_names.setdefault(component.name, set()).add(component.resolved_version)
    matched: set[tuple[str, str]] = set()
    sbom_only: list[Component] = []
    for component in sbom_components:
        version = component.resolved_version
        if version is None:
            sbom_only.append(component)
            continue
        key = (component.name, version)
        lock_matches = lock_index.get(key, [])
        if not lock_matches:
            sbom_only.append(component)
            known = lock_names.get(component.name)
            if known:
                warnings.append(
                    InventoryWarning(
                        code="version_discrepancy",
                        message="SBOM and lockfile record different versions; both are kept",
                        component=component.name,
                        blocks_completeness=True,
                    )
                )
            else:
                warnings.append(
                    InventoryWarning(
                        code="sbom_only",
                        message="SBOM component has no matching lockfile name and version",
                        component=component.name,
                        blocks_completeness=True,
                    )
                )
            continue
        matched.add(key)
        for lock_component in lock_matches:
            sources = list(lock_component.metadata.get("sources") or ["lockfile"])
            if "syft" not in sources:
                sources.append("syft")
            lock_component.metadata["sources"] = sources
            if not lock_component.dependency_paths and component.dependency_paths:
                lock_component.dependency_paths = component.dependency_paths
                lock_component.direct = component.direct
            elif (
                component.dependency_paths
                and lock_component.dependency_paths
                and component.dependency_paths != lock_component.dependency_paths
            ):
                lock_component.metadata["sbom_dependency_paths"] = component.dependency_paths
                warnings.append(
                    InventoryWarning(
                        code="path_discrepancy",
                        message="SBOM dependency paths differ; lockfile paths were kept",
                        component=component.name,
                        blocks_completeness=True,
                    )
                )
            elif not component.dependency_paths and lock_component.dependency_paths:
                lock_component.metadata["paths_recovered_from_lockfile"] = True
    warnings.extend(_lockfile_only(lock_components, matched))
    combined = [*lock_components, *sbom_only]
    combined.sort(
        key=lambda item: (
            item.name,
            item.resolved_version or "",
            str(item.metadata.get("lock_path", "")),
        )
    )
    return combined, warnings


def _lockfile_only(
    lock_components: list[Component], matched: set[tuple[str, str]]
) -> list[InventoryWarning]:
    warnings: list[InventoryWarning] = []
    reported: set[tuple[str, str]] = set()
    for component in lock_components:
        if component.resolved_version is None:
            continue
        key = (component.name, component.resolved_version)
        if key in matched or key in reported:
            continue
        reported.add(key)
        sources = list(component.metadata.get("sources") or ["lockfile"])
        component.metadata["sources"] = sources
        warnings.append(
            InventoryWarning(
                code="lockfile_only",
                message="Lockfile component was not present in the SBOM and was kept",
                component=component.name,
                blocks_completeness=True,
            )
        )
    return warnings
