"""Redacted provider failures. Secrets passed in are scrubbed and not retained."""

from __future__ import annotations

_MIN_SECRET_LENGTH = 8


def redact(text: str, secrets: tuple[str, ...]) -> str:
    cleaned = text
    for secret in secrets:
        if secret and len(secret) >= _MIN_SECRET_LENGTH:
            cleaned = cleaned.replace(secret, "[redacted]")
    return cleaned


class ProviderError(Exception):
    """A failed provider operation. ``str(error)`` is safe to log."""

    def __init__(self, *, provider: str, kind: str, reason: str, secrets: tuple[str, ...] = ()):
        self.provider = provider
        self.kind = kind
        self.reason = redact(reason, secrets)[:300]
        super().__init__(f"{provider}: {kind}: {self.reason}")


def reject_if_secret(value: str, *, provider: str, secrets: tuple[str, ...], what: str) -> None:
    for secret in secrets:
        if secret and len(secret) >= _MIN_SECRET_LENGTH and secret in value:
            raise ProviderError(
                provider=provider,
                kind="invalid_response",
                reason=f"{what} contained a credential and was discarded",
            )
