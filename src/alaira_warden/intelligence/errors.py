"""Source failures. Messages stay on a fixed vocabulary and never carry response bodies."""

from __future__ import annotations

import re

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

_REASON = re.compile(r"^[a-z0-9_]+$")


class SourceError(Exception):
    """A classified failure. ``str(error)`` is safe to log."""

    def __init__(
        self,
        *,
        category: str,
        source: str,
        operation: str,
        status_code: int | None = None,
        retry_after_seconds: float | None = None,
        reason: str | None = None,
    ) -> None:
        if category not in CATEGORIES:
            raise ValueError(f"Unknown source error category: {category}")
        self.category = category
        self.source = source
        self.operation = operation
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds
        self.reason = reason if reason and _REASON.fullmatch(reason) else None
        code = f"{category}/{self.reason}" if self.reason else category
        super().__init__(f"{source} {operation} failed ({code})")

    @property
    def warning_code(self) -> str:
        return self.reason or self.category
