"""Categorized failures for inventory reads and imports."""

ErrorCategory = str

CATEGORIES = frozenset(
    {
        "configuration",
        "unauthorized",
        "forbidden",
        "rate_limited",
        "unavailable",
        "timeout",
        "invalid_response",
        "unsupported",
        "budget_exceeded",
    }
)


class InventoryError(Exception):
    """A failed inventory operation that names a roadmap error category."""

    def __init__(self, category: ErrorCategory, message: str):
        if category not in CATEGORIES:
            raise ValueError(f"Unknown inventory error category: {category}")
        self.category = category
        super().__init__(message)
