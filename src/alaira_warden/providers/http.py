"""Small HTTP transport. Redirects are never followed."""

from __future__ import annotations

import http.client
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from alaira_warden.providers.errors import ProviderError


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes | None
    timeout: float


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str


class TransportFailure(Exception):
    def __init__(self, kind: str, reason: str):
        self.kind = kind
        self.reason = reason
        super().__init__(reason)


class Transport(Protocol):
    def send(self, request: HttpRequest) -> HttpResponse: ...


class UrllibTransport:
    """Stdlib client. It does not follow redirects and does not read environment proxies."""

    def send(self, request: HttpRequest) -> HttpResponse:
        parsed = urlsplit(request.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise TransportFailure("offline", "unsupported URL")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        connection_cls = (
            http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        )
        connection = connection_cls(parsed.hostname, port, timeout=request.timeout)
        try:
            connection.request(
                request.method,
                path,
                body=request.body,
                headers={str(key): str(value) for key, value in request.headers.items()},
            )
            response = connection.getresponse()
            payload = response.read()
            headers = {key.lower(): value for key, value in response.getheaders()}
            return HttpResponse(
                status=response.status,
                headers=headers,
                body=payload,
                url=request.url,
            )
        except TimeoutError:
            raise TransportFailure("timeout", "request timed out") from None
        except OSError:
            raise TransportFailure("offline", "provider unreachable") from None
        finally:
            connection.close()


def header(response: HttpResponse, name: str) -> str:
    return response.headers.get(name.lower(), "")


def ensure_attempts(max_attempts: int, *, provider: str) -> int:
    if (
        isinstance(max_attempts, bool)
        or not isinstance(max_attempts, int)
        or max_attempts < 1
        or max_attempts > 3
    ):
        raise ProviderError(
            provider=provider,
            kind="unsupported",
            reason="max_attempts must be an integer from 1 to 3",
        )
    return max_attempts


def ensure_timeout(timeout: float, *, ceiling: float, provider: str) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, int | float):
        raise ProviderError(
            provider=provider,
            kind="unsupported",
            reason="timeout must be a finite number of seconds",
        )
    if timeout <= 0 or timeout > ceiling:
        raise ProviderError(
            provider=provider,
            kind="unsupported",
            reason=f"timeout must be greater than 0 and at most {ceiling:g} seconds",
        )
    return float(timeout)
