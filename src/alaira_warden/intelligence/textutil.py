"""Small parsers shared by the source normalizers."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from alaira_warden.intelligence.errors import SourceError

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
GHSA_RE = re.compile(r"^GHSA(?:-[A-Z0-9]{4}){3}$", re.IGNORECASE)
_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"]+")
_SECRET_QUERY = frozenset(
    {"apikey", "api_key", "access_token", "token", "key", "password", "client_secret", "secret"}
)


def parse_timestamp(value: object) -> datetime | None:
    """Parse an ISO-8601 timestamp. ``None`` means the source did not provide one."""

    if value is None or value == "":
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        text = text + "T00:00:00+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def require_aware(value: datetime, *, source: str, operation: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise SourceError(
            category="unsupported",
            source=source,
            operation=operation,
            reason="naive_datetime",
        )
    return value.astimezone(UTC)


def nvd_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_identifier(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or any(character.isspace() for character in text):
        return None
    upper = text.upper()
    if CVE_RE.fullmatch(upper):
        return upper
    if GHSA_RE.fullmatch(upper):
        return "GHSA-" + "-".join(part.lower() for part in upper.split("-")[1:])
    return text


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def clean_reference(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    parsed = urlsplit(text)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    names = {name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    if names & _SECRET_QUERY:
        return None
    return text


def reference_list(value: object) -> list[str]:
    if isinstance(value, str):
        items: list[object] = [value]
    elif isinstance(value, list):
        items = list(value)
    else:
        return []
    found: list[str] = []
    for item in items:
        if isinstance(item, dict):
            candidate = clean_reference(item.get("url"))
        else:
            candidate = clean_reference(item)
        if candidate and candidate not in found:
            found.append(candidate)
    return found


def urls_in_text(value: object) -> list[str]:
    if not isinstance(value, str):
        return []
    found: list[str] = []
    for match in _URL_IN_TEXT.findall(value):
        candidate = clean_reference(match.rstrip(").,;"))
        if candidate and candidate not in found:
            found.append(candidate)
    return found


def dump_cursor(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def load_cursor(cursor: str, *, source: str, operation: str) -> dict[str, Any]:
    try:
        payload = json.loads(cursor)
    except json.JSONDecodeError:
        raise SourceError(
            category="unsupported", source=source, operation=operation, reason="invalid_cursor"
        ) from None
    if not isinstance(payload, dict) or payload.get("v") != 1 or payload.get("source") != source:
        raise SourceError(
            category="unsupported", source=source, operation=operation, reason="invalid_cursor"
        )
    return payload


def ensure_public_url(
    url: str,
    *,
    source: str,
    operation: str,
    hosts: frozenset[str],
    path_allowed: Any,
) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in hosts
        or parsed.username
        or parsed.password
    ):
        raise SourceError(
            category="unsupported", source=source, operation=operation, reason="host_not_allowed"
        )
    names = {name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    if names & _SECRET_QUERY:
        raise SourceError(
            category="unsupported", source=source, operation=operation, reason="secret_in_url"
        )
    if not path_allowed(parsed.path):
        raise SourceError(
            category="unsupported", source=source, operation=operation, reason="path_not_allowed"
        )
