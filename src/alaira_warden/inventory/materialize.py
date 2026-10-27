"""Write already-fetched repository files without following escapes."""

from collections.abc import Mapping
from pathlib import Path

from alaira_warden.inventory.errors import InventoryError
from alaira_warden.inventory.limits import InventoryLimits
from alaira_warden.inventory.paths import normalize_repo_path


def materialize_files(
    root: Path, files: Mapping[str, bytes], *, limits: InventoryLimits | None = None
) -> None:
    limits = limits or InventoryLimits()
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise InventoryError("configuration", "Checkout root must be an absolute directory")
    root_real = root.resolve()
    if len(files) > limits.max_files:
        raise InventoryError("budget_exceeded", "Too many files to materialize")
    total = 0
    for relative, content in files.items():
        if not isinstance(content, bytes):
            raise InventoryError("unsupported", "File content must be bytes")
        if len(content) > limits.max_file_bytes:
            raise InventoryError("budget_exceeded", "File exceeds the size limit")
        total += len(content)
        if total > limits.max_total_bytes:
            raise InventoryError("budget_exceeded", "Checkout exceeds the total size limit")
        relative_path = normalize_repo_path(relative)
        destination = root.joinpath(*relative_path.split("/"))
        _require_inside(root_real, destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        _require_inside(root_real, destination)
        if destination.is_symlink():
            target = destination.resolve()
            if not target.is_relative_to(root_real):
                raise InventoryError("unsupported", "Symlink points outside the checkout")
            raise InventoryError("unsupported", "Refusing to write through a symlink")
        destination.write_bytes(content)
        if not destination.resolve().is_relative_to(root_real):
            destination.unlink(missing_ok=True)
            raise InventoryError("unsupported", "Written file resolved outside the checkout")


def _require_inside(root_real: Path, destination: Path) -> None:
    parent = destination.parent if not destination.exists() else destination
    if parent.exists() or parent.is_symlink():
        parent_real = parent.resolve()
        if not parent_real.is_relative_to(root_real):
            raise InventoryError("unsupported", "Path escapes the checkout")
