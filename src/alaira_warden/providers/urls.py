"""URL normalization. Embedded credentials are rejected before any request."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from alaira_warden.providers.errors import ProviderError

_METERLESS_SUFFIXES = ("/v1/chat/completions", "/v1/models", "/healthz", "/v1")
_NVIDIA_SUFFIXES = ("/v1/chat/completions", "/v1")
_ZETARIS_SUFFIXES = (
    "/api/v1.0/sql-editor/sqls/run-query",
    "/api/v1.0/auth/login",
    "/api/v1.0",
    "/api/proxy/sql-editor/sqls/run-query",
    "/api/proxy/query/sql/start",
    "/api/auth/login",
    "/api/proxy/query",
    "/api",
)
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_HTTP_HOSTS = _LOOPBACK | {"host.docker.internal"}
_DOCKERENV = Path("/.dockerenv")


def _fail(provider: str, reason: str) -> None:
    raise ProviderError(provider=provider, kind="unsupported", reason=reason)


def _reject_embedded_credentials(provider: str, parsed) -> None:
    if parsed.username is not None or parsed.password is not None:
        _fail(provider, "URLs with embedded credentials are rejected")
    if parsed.fragment or parsed.query:
        _fail(provider, "URLs with embedded credentials are rejected")


def _add_scheme(raw: str) -> str:
    if "://" in raw:
        return raw
    host = raw.split("/", 1)[0]
    if host.startswith("["):
        hostname = host.split("]")[0].removeprefix("[")
    else:
        hostname = host.split(":")[0]
    scheme = "http" if hostname.lower() in _HTTP_HOSTS else "https"
    return f"{scheme}://{raw}"


def _strip_suffixes(path: str, suffixes: tuple[str, ...]) -> str:
    remainder = path.rstrip("/")
    changed = True
    while changed:
        changed = False
        for suffix in suffixes:
            if remainder.endswith(suffix):
                remainder = remainder[: -len(suffix)].rstrip("/")
                changed = True
                break
    return remainder


def _origin(
    provider: str,
    raw: str,
    *,
    suffixes: tuple[str, ...],
    allow_http_loopback: bool,
) -> str:
    value = raw.strip()
    if not value:
        _fail(provider, "base URL is empty")
    value = _add_scheme(value)
    parsed = urlsplit(value)
    _reject_embedded_credentials(provider, parsed)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        _fail(provider, "base URL scheme or host is invalid")
    hostname = parsed.hostname.lower()
    if parsed.scheme == "http" and not (allow_http_loopback and hostname in _HTTP_HOSTS):
        _fail(provider, "cleartext URLs are limited to the Meterless loopback runtime")
    remainder = _strip_suffixes(parsed.path or "", suffixes)
    if remainder not in {"", "/"}:
        _fail(provider, "base URL path is not part of the verified contract")
    netloc = parsed.netloc.lower()
    return urlunsplit((parsed.scheme, netloc, "", "", ""))


def rewrite_loopback_for_container(url: str) -> str:
    """Map host loopback to host.docker.internal when the API runs in Docker."""
    value = url.strip()
    if not value or not _DOCKERENV.exists():
        return url
    parsed = urlsplit(_add_scheme(value))
    host = (parsed.hostname or "").lower()
    if host not in _LOOPBACK:
        return url
    port = parsed.port
    netloc = f"host.docker.internal:{port}" if port else "host.docker.internal"
    return urlunsplit((parsed.scheme or "http", netloc, parsed.path, parsed.query, parsed.fragment))


def meterless_endpoints(base_url: str) -> tuple[str, str]:
    """Return ``(origin, api_base)`` with ``api_base`` ending in exactly one ``/v1``."""
    origin = _origin(
        "meterless",
        base_url,
        suffixes=_METERLESS_SUFFIXES,
        allow_http_loopback=True,
    )
    host = urlsplit(origin).hostname or ""
    if host == "integrate.api.nvidia.com":
        _fail("meterless", "refusing to send the Meterless token to the NVIDIA host")
    return origin, f"{origin}/v1"


def nvidia_api_base(base_url: str) -> str:
    origin = _origin("nvidia", base_url, suffixes=_NVIDIA_SUFFIXES, allow_http_loopback=False)
    parsed = urlsplit(origin)
    if parsed.hostname != "integrate.api.nvidia.com":
        _fail("nvidia", "the NVIDIA key is only sent to integrate.api.nvidia.com")
    return f"{origin}/v1"


def zetaris_origin(base_url: str) -> str:
    origin = _origin("zetaris", base_url, suffixes=_ZETARIS_SUFFIXES, allow_http_loopback=True)
    host = urlsplit(origin).hostname or ""
    if host == "integrate.api.nvidia.com":
        _fail("zetaris", "refusing to send the Zetaris credential to the NVIDIA host")
    return origin
