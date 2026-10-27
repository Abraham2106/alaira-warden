"""Remove credential material from messages that might be stored or shown."""

import re

_USERINFO = re.compile(r"(https?://)([^/\s:@]+):([^/\s@]+)@")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]+")


def redact_text(value: str, secrets: tuple[str, ...] = ()) -> str:
    redacted = value
    for secret in secrets:
        if secret and len(secret) >= 8:
            redacted = redacted.replace(secret, "[redacted]")
    redacted = _USERINFO.sub(r"\1", redacted)
    redacted = _BEARER.sub("Bearer [redacted]", redacted)
    return redacted


def sanitize_url(url: str, secrets: tuple[str, ...] = ()) -> str:
    """Drop userinfo and refuse a URL that still contains a known secret."""
    cleaned = redact_text(url, secrets)
    host = cleaned.split("://", 1)[-1].split("/", 1)[0]
    if "@" in host:
        raise ValueError("URL still contains userinfo")
    for secret in secrets:
        if secret and len(secret) >= 8 and secret in cleaned:
            raise ValueError("URL still contains a secret")
    return cleaned
