"""Authorized GitHub read of npm manifests at one immutable commit.

Transport is injected. This module does not open sockets and does not put
credentials in URLs, errors, or returned file text.
"""

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

from alaira_warden.inventory.errors import InventoryError
from alaira_warden.inventory.limits import InventoryLimits
from alaira_warden.inventory.models import InventoryWarning, validate_repository_name
from alaira_warden.inventory.paths import normalize_repo_path
from alaira_warden.inventory.redact import redact_text

API_VERSION = "2022-11-28"
USER_AGENT = "alaira-warden-inventory"
_DOWNLOADED = frozenset({"package.json", "package-lock.json"})
_OTHER_LOCKS = frozenset({"yarn.lock", "pnpm-lock.yaml"})


class HTTPResponse:
    def __init__(self, status: int, body: bytes, headers: Mapping[str, str] | None = None):
        self.status = status
        self.body = body
        self.headers = {str(key).lower(): value for key, value in (headers or {}).items()}


class GitHubTransport:
    """Structural stand-in. Callers pass any object with this request method."""

    def request(
        self, method: str, url: str, headers: Mapping[str, str], timeout_seconds: float
    ) -> HTTPResponse:
        raise NotImplementedError


@dataclass
class RepositoryRead:
    repository: str
    commit_sha: str
    requested_ref: str
    files: dict[str, str]
    warnings: list[InventoryWarning] = field(default_factory=list)


@dataclass
class _Deadline:
    seconds: float
    clock: Callable[[], float]
    end: float = field(init=False)

    def __post_init__(self) -> None:
        self.end = self.clock() + self.seconds

    def remaining(self) -> float:
        left = self.end - self.clock()
        if left <= 0:
            raise InventoryError("timeout", "Inventory read exceeded the time limit")
        return left


def read_github_repository(
    *,
    repository: str,
    ref: str,
    transport: GitHubTransport,
    allowed_repositories: set[str] | frozenset[str],
    token: str,
    limits: InventoryLimits | None = None,
    api_base: str = "https://api.github.com",
    clock: Callable[[], float] = time.monotonic,
) -> RepositoryRead:
    limits = limits or InventoryLimits()
    try:
        repository = validate_repository_name(repository)
    except ValueError as exc:
        raise InventoryError("invalid_response", "Repository name is invalid") from exc
    if repository not in allowed_repositories:
        raise InventoryError("forbidden", "Repository is not authorized for inventory reads")
    ref = _validate_ref(ref)
    base = _validate_api_base(api_base)
    deadline = _Deadline(limits.timeout_seconds, clock)
    secrets = (token,) if token else ()
    try:
        commit_payload = _get_json(
            transport,
            f"{base}/repos/{_repo_path(repository)}/commits/{quote(ref, safe='')}",
            token=token,
            limits=limits,
            deadline=deadline,
            raw=False,
        )
        sha = _commit_sha(commit_payload, ref)
        tree_payload = _get_json(
            transport,
            f"{base}/repos/{_repo_path(repository)}/git/trees/{sha}?recursive=1",
            token=token,
            limits=limits,
            deadline=deadline,
            raw=False,
        )
        selected, warnings = _select_tree(tree_payload, limits)
        files: dict[str, str] = {}
        total = 0
        for path, blob_sha, size in selected:
            if size is not None and size > limits.max_file_bytes:
                raise InventoryError("budget_exceeded", "A manifest exceeds the file size limit")
            body = _get_bytes(
                transport,
                f"{base}/repos/{_repo_path(repository)}/git/blobs/{blob_sha}",
                token=token,
                limits=limits,
                deadline=deadline,
                raw=True,
            )
            if len(body) > limits.max_file_bytes:
                raise InventoryError("budget_exceeded", "A manifest exceeds the file size limit")
            total += len(body)
            if total > limits.max_total_bytes:
                raise InventoryError("budget_exceeded", "Manifests exceed the total size limit")
            try:
                files[path] = body.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise InventoryError("invalid_response", "A manifest is not UTF-8 text") from exc
        return RepositoryRead(repository, sha, ref, files, warnings)
    except InventoryError as exc:
        raise InventoryError(exc.category, redact_text(str(exc), secrets)) from None


def _repo_path(repository: str) -> str:
    owner, name = repository.split("/")
    return f"{quote(owner, safe='')}/{quote(name, safe='')}"


def _validate_ref(ref: str) -> str:
    if (
        not ref
        or len(ref) > 256
        or any(char.isspace() or char in {"\x00", "\\"} for char in ref)
        or ".." in ref
        or "@" in ref
        or "://" in ref
    ):
        raise InventoryError("invalid_response", "Git reference is invalid")
    return ref


def _validate_api_base(api_base: str) -> str:
    parts = urlsplit(api_base)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        raise InventoryError("configuration", "GitHub API base URL is invalid")
    return f"https://{parts.netloc}".rstrip("/")


def _headers(token: str, *, raw: bool) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": API_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _request(
    transport: GitHubTransport,
    url: str,
    *,
    token: str,
    limits: InventoryLimits,
    deadline: _Deadline,
    raw: bool,
) -> HTTPResponse:
    if urlsplit(url).username or urlsplit(url).password or (token and token in url):
        raise InventoryError("configuration", "GitHub request URL is invalid")
    timeout = deadline.remaining()
    try:
        response = transport.request("GET", url, _headers(token, raw=raw), timeout)
    except TimeoutError as exc:
        raise InventoryError("timeout", "GitHub read timed out") from exc
    except InventoryError:
        raise
    except Exception as exc:
        raise InventoryError("unavailable", "GitHub read failed") from exc
    if len(response.body) > limits.max_response_bytes:
        raise InventoryError("budget_exceeded", "GitHub response exceeds the size limit")
    if response.status != 200:
        raise _status_error(response.status, response.headers.get("x-ratelimit-remaining"))
    return response


def _get_json(
    transport: GitHubTransport,
    url: str,
    *,
    token: str,
    limits: InventoryLimits,
    deadline: _Deadline,
    raw: bool,
) -> dict:
    response = _request(transport, url, token=token, limits=limits, deadline=deadline, raw=raw)
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("invalid_response", "GitHub response was not JSON") from exc
    if not isinstance(payload, dict):
        raise InventoryError("invalid_response", "GitHub response was not a JSON object")
    return payload


def _get_bytes(
    transport: GitHubTransport,
    url: str,
    *,
    token: str,
    limits: InventoryLimits,
    deadline: _Deadline,
    raw: bool,
) -> bytes:
    return _request(transport, url, token=token, limits=limits, deadline=deadline, raw=raw).body


def _status_error(status: int, remaining: str | None) -> InventoryError:
    if status == 401:
        return InventoryError("unauthorized", "GitHub rejected the credential")
    if status == 429 or (status == 403 and remaining == "0"):
        return InventoryError("rate_limited", "GitHub rate limit exhausted")
    if status == 403:
        return InventoryError("forbidden", "GitHub forbade the read")
    if status == 404:
        return InventoryError("unavailable", "GitHub resource not found")
    return InventoryError("unavailable", f"GitHub request failed with status {status}")


def _commit_sha(payload: dict, ref: str) -> str:
    sha = payload.get("sha")
    if not isinstance(sha, str) or len(sha) != 40:
        raise InventoryError("invalid_response", "GitHub commit response has no immutable sha")
    sha = sha.lower()
    if any(char not in "0123456789abcdef" for char in sha):
        raise InventoryError("invalid_response", "GitHub commit sha is not hexadecimal")
    requested = ref.lower()
    hex_ref = len(ref) == 40 and all(char in "0123456789abcdef" for char in requested)
    if hex_ref and requested != sha:
        raise InventoryError(
            "invalid_response", "GitHub commit sha did not match the requested commit"
        )
    return sha


def _select_tree(
    payload: dict, limits: InventoryLimits
) -> tuple[list[tuple[str, str, int | None]], list[InventoryWarning]]:
    if payload.get("truncated") is True:
        raise InventoryError("budget_exceeded", "GitHub tree listing was truncated")
    tree = payload.get("tree")
    if not isinstance(tree, list):
        raise InventoryError("invalid_response", "GitHub tree response has no tree")
    if len(tree) > limits.max_tree_entries:
        raise InventoryError("budget_exceeded", "GitHub tree exceeds the entry limit")
    warnings: list[InventoryWarning] = []
    selected: list[tuple[str, str, int | None]] = []
    for item in tree:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        path = item["path"]
        name = path.rsplit("/", 1)[-1]
        if "/node_modules/" in f"/{path}" or path.startswith("node_modules/"):
            continue
        if name in _OTHER_LOCKS:
            warnings.append(
                InventoryWarning(
                    code="unsupported_lockfile",
                    message="A non-npm lockfile is present and was not parsed",
                    path=path,
                    blocks_completeness=True,
                )
            )
            continue
        if name not in _DOWNLOADED:
            continue
        if name == "package-lock.json" and path != "package-lock.json":
            warnings.append(
                InventoryWarning(
                    code="nested_lockfile_ignored",
                    message="Nested package-lock.json files are not merged",
                    path=path,
                    blocks_completeness=True,
                )
            )
            continue
        try:
            safe_path = normalize_repo_path(path)
        except InventoryError as exc:
            raise InventoryError("unsupported", "Manifest path is unsafe") from exc
        if item.get("type") != "blob":
            warnings.append(
                InventoryWarning(
                    code="symlink_rejected",
                    message="Manifest is not a regular file and was not followed",
                    path=safe_path,
                    blocks_completeness=True,
                )
            )
            continue
        mode = str(item.get("mode") or "")
        if mode == "120000":
            warnings.append(
                InventoryWarning(
                    code="symlink_rejected",
                    message="Symlinked manifest was not followed",
                    path=safe_path,
                    blocks_completeness=True,
                )
            )
            continue
        blob_sha = item.get("sha")
        if not isinstance(blob_sha, str) or not blob_sha:
            raise InventoryError("invalid_response", "GitHub tree entry has no blob sha")
        size = item.get("size") if isinstance(item.get("size"), int) else None
        selected.append((safe_path, blob_sha, size))
    if len(selected) > limits.max_files:
        raise InventoryError("budget_exceeded", "Too many manifests to read")
    return selected, warnings
