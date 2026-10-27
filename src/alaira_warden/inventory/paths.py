"""Repository-relative paths that cannot escape a checkout."""

from alaira_warden.inventory.errors import InventoryError


def normalize_repo_path(value: str) -> str:
    """Accept a single relative slash-separated path inside a checkout."""
    if not isinstance(value, str) or value == "":
        raise InventoryError("unsupported", "Repository path is empty")
    if (
        value.startswith(("/", "\\"))
        or "\\" in value
        or ":" in value
        or "\x00" in value
        or value.startswith("//")
    ):
        raise InventoryError("unsupported", "Repository path is absolute or unsupported")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise InventoryError("unsupported", "Repository path escapes the checkout")
    if any(len(part) > 240 for part in parts) or len(value) > 512:
        raise InventoryError("budget_exceeded", "Repository path exceeds the length limit")
    return "/".join(parts)
