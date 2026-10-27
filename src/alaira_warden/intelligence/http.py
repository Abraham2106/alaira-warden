"""Bounded HTTPS calls. Redirects are refused. Response bodies never enter errors."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from http.client import HTTPSConnection
from typing import Any, Protocol
from urllib.parse import urlsplit

from alaira_warden.intelligence.errors import SourceError
from alaira_warden.intelligence.textutil import ensure_public_url

MAX_RESPONSE_BYTES = 32 * 1024 * 1024
USER_AGENT = "alaira-warden/0.1"
RETRYABLE = frozenset({"timeout", "unavailable", "rate_limited"})


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes | None
    timeout_seconds: float


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class JsonResult:
    status_code: int
    headers: Mapping[str, str]
    payload: Any


class Transport(Protocol):
    def send(self, request: HttpRequest) -> HttpResponse: ...


@dataclass
class WorkBudget:
    """Finite work shared across pages and retries. The object is mutated in place."""

    max_requests: int = 8
    max_retries: int = 2
    timeout_seconds: float = 20.0
    max_wait_seconds: float = 2.0
    deadline_seconds: float = 60.0
    requests_used: int = 0
    _started: float = field(default_factory=time.monotonic, repr=False)

    def __post_init__(self) -> None:
        if self.max_requests < 1 or self.max_retries < 0:
            raise ValueError("request and retry limits must be finite")
        if self.timeout_seconds <= 0 or self.max_wait_seconds < 0 or self.deadline_seconds < 0:
            raise ValueError("time limits must be finite")

    def remaining_requests(self) -> int:
        return self.max_requests - self.requests_used

    def expired(self) -> bool:
        return (time.monotonic() - self._started) >= self.deadline_seconds

    def consume(self, *, source: str, operation: str) -> None:
        if self.remaining_requests() <= 0 or self.expired():
            raise SourceError(
                category="budget_exceeded",
                source=source,
                operation=operation,
                reason="budget_exceeded",
            )
        self.requests_used += 1


class UrllibTransport:
    """HTTPS via ``http.client``. Redirects are not followed."""

    def send(self, request: HttpRequest) -> HttpResponse:
        parsed = urlsplit(request.url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise SourceError(
                category="unsupported",
                source="transport",
                operation="send",
                reason="host_not_allowed",
            )
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        connection = HTTPSConnection(
            parsed.hostname, parsed.port or 443, timeout=request.timeout_seconds
        )
        try:
            connection.request(
                request.method,
                path,
                body=request.body,
                headers={str(key): str(value) for key, value in request.headers.items()},
            )
            response = connection.getresponse()
            status = response.status
            headers = {key.lower(): value for key, value in response.getheaders()}
            if status in {301, 302, 303, 307, 308}:
                raise SourceError(
                    category="unsupported",
                    source="transport",
                    operation="send",
                    status_code=status,
                    reason="redirect_refused",
                )
            body = response.read(MAX_RESPONSE_BYTES + 1)
        except TimeoutError:
            raise SourceError(
                category="timeout", source="transport", operation="send", reason="timeout"
            ) from None
        except SourceError:
            raise
        except OSError:
            raise SourceError(
                category="unavailable",
                source="transport",
                operation="send",
                reason="connection_failed",
            ) from None
        finally:
            connection.close()
        if len(body) > MAX_RESPONSE_BYTES:
            raise SourceError(
                category="invalid_response",
                source="transport",
                operation="send",
                reason="response_too_large",
            )
        return HttpResponse(status, headers, body)


def parse_retry_after(value: str | None, *, now: datetime) -> float | None:
    if value is None or not value.strip():
        return None
    text = value.strip()
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=UTC)
    return max(0.0, (parsed.astimezone(UTC) - now).total_seconds())


def _rate_limited(status: int, headers: Mapping[str, str], body: bytes) -> bool:
    if status == 429:
        return True
    if status != 403:
        return False
    if headers.get("x-ratelimit-remaining") == "0" or "retry-after" in headers:
        return True
    sample = body[:2000].decode("utf-8", "replace").lower()
    return "rate limit" in sample


def _classify(
    response: HttpResponse, *, source: str, operation: str, now: datetime
) -> SourceError | None:
    status = response.status_code
    if 200 <= status < 300 or status == 404:
        return None
    headers = response.headers
    if status == 401:
        category, reason = "unauthorized", "http_401"
    elif _rate_limited(status, headers, response.body):
        category, reason = "rate_limited", "http_429" if status == 429 else "rate_limited"
    elif status == 403:
        category, reason = "forbidden", "http_403"
    elif status == 400:
        category, reason = "unsupported", "http_400"
    elif status in {408, 504}:
        category, reason = "timeout", f"http_{status}"
    elif status in {500, 502, 503}:
        category, reason = "unavailable", f"http_{status}"
    else:
        category, reason = "unsupported", "unexpected_status"
    retry_after = parse_retry_after(headers.get("retry-after"), now=now)
    return SourceError(
        category=category,
        source=source,
        operation=operation,
        status_code=status,
        retry_after_seconds=retry_after,
        reason=reason,
    )


def request_json(
    *,
    source: str,
    operation: str,
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: Mapping[str, Any] | None,
    transport: Transport,
    budget: WorkBudget,
    sleeper: Callable[[float], None],
    hosts: frozenset[str],
    path_allowed: Any,
    now: Callable[[], datetime] | None = None,
) -> JsonResult:
    ensure_public_url(
        url, source=source, operation=operation, hosts=hosts, path_allowed=path_allowed
    )
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    outbound = {str(key): str(value) for key, value in headers.items()}
    for value in outbound.values():
        if "\n" in value or "\r" in value:
            raise SourceError(
                category="configuration",
                source=source,
                operation=operation,
                reason="invalid_header",
            )
    if payload is not None:
        outbound.setdefault("Content-Type", "application/json")
    outbound.setdefault("Accept", "application/json")
    outbound.setdefault("User-Agent", USER_AGENT)
    clock = now or (lambda: datetime.now(UTC))
    attempts = 0
    last_error: SourceError | None = None
    while True:
        try:
            budget.consume(source=source, operation=operation)
        except SourceError as budget_error:
            if last_error is not None:
                raise last_error from None
            raise budget_error from None
        try:
            response = transport.send(
                HttpRequest(
                    method=method.upper(),
                    url=url,
                    headers=outbound,
                    body=payload,
                    timeout_seconds=budget.timeout_seconds,
                )
            )
        except TimeoutError:
            last_error = SourceError(
                category="timeout", source=source, operation=operation, reason="timeout"
            )
            response = None
        except SourceError as error:
            last_error = error
            response = None
        except OSError:
            last_error = SourceError(
                category="unavailable",
                source=source,
                operation=operation,
                reason="connection_failed",
            )
            response = None
        else:
            last_error = _classify(response, source=source, operation=operation, now=clock())
            if last_error is None:
                if response.status_code == 404:
                    return JsonResult(response.status_code, dict(response.headers), None)
                try:
                    parsed = json.loads(response.body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise SourceError(
                        category="invalid_response",
                        source=source,
                        operation=operation,
                        status_code=response.status_code,
                        reason="invalid_json",
                    ) from None
                return JsonResult(response.status_code, dict(response.headers), parsed)
        if last_error.category in RETRYABLE and attempts < budget.max_retries:
            wait = last_error.retry_after_seconds
            if wait is None:
                wait = min(budget.max_wait_seconds, 0.25 * (2**attempts))
            if wait > budget.max_wait_seconds:
                raise last_error
            attempts += 1
            sleeper(wait)
            continue
        raise last_error


def link_next(headers: Mapping[str, str]) -> str | None:
    header = headers.get("link")
    if not header:
        return None
    for part in header.split(","):
        piece = part.strip()
        if not piece.startswith("<") or ";" not in piece:
            continue
        url, _, rest = piece[1:].partition(">")
        if 'rel="next"' in rest or "rel=next" in rest:
            return url
    return None
