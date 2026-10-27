"""Zetaris read client.

Login is ``GET /api/v1.0/auth/login`` (basic auth, ``X-Request-ID``, ``X-Org-ID``)
from the official access guide. A bounded read is
``POST /api/v1.0/sql-editor/sqls/run-query`` with body ``{"sql": ...}``, bearer
API key, and the same two headers, from the official pipeline-scheduling
example. The Redoc page did not return a machine-readable spec, so no other
path is called.

The scaffold API key is the console bearer. It does not replace the instance
URL, organization id, or the login password. Login tokens are not reused as
the query credential and are not returned.
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from alaira_warden.providers.chat import (
    decode_object,
    failure_from_status,
    safe_reason,
    send_with_budget,
)
from alaira_warden.providers.contract import ProviderCheck, ZetarisQueryResult
from alaira_warden.providers.errors import ProviderError, reject_if_secret
from alaira_warden.providers.http import HttpRequest, Transport, UrllibTransport, ensure_timeout
from alaira_warden.providers.urls import zetaris_origin

_FORBIDDEN = re.compile(
    r"(?i)\b(insert|update|delete|drop|alter|create|merge|grant|revoke|copy|call|"
    r"execute|exec|truncate|comment|upsert|into)\b"
)
_LIMIT = re.compile(r"(?i)\blimit\s+(\d+)\b")
_SOURCE = re.compile(r"(?i)\b(?:from|join)\s+([A-Za-z_][\w.]*)")
_TIMEOUT_CEILING = 60.0


def _now() -> datetime:
    return datetime.now(UTC)


def validate_read_sql(statement: str) -> tuple[str, int, list[str]]:
    text = statement.strip()
    if text.endswith(";"):
        text = text[:-1].strip()
    if not text or ";" in text or "--" in text or "/*" in text:
        raise ProviderError(
            provider="zetaris",
            kind="unsupported",
            reason="only one comment-free read statement is accepted",
        )
    if not re.match(r"(?is)^(select|with)\b", text) or _FORBIDDEN.search(text):
        raise ProviderError(
            provider="zetaris",
            kind="unsupported",
            reason="only a single SELECT or WITH read is accepted",
        )
    limits = _LIMIT.findall(text)
    if len(limits) != 1:
        raise ProviderError(
            provider="zetaris",
            kind="unsupported",
            reason="the statement must include one LIMIT from 1 to 100",
        )
    limit = int(limits[0])
    if limit < 1 or limit > 100:
        raise ProviderError(
            provider="zetaris",
            kind="unsupported",
            reason="the statement must include one LIMIT from 1 to 100",
        )
    sources: list[str] = []
    for source in _SOURCE.findall(text):
        if source not in sources:
            sources.append(source)
    return text, limit, sources


class ZetarisClient:
    def __init__(
        self,
        *,
        base_url: str,
        org_id: str,
        api_key: str = "",
        username: str = "",
        password: str = "",
        transport: Transport | None = None,
        clock: Callable[[], datetime] | None = None,
        request_id_factory: Callable[[], str] | None = None,
        max_attempts: int = 1,
    ):
        self._base_url = base_url
        self._org_id = org_id.strip()
        self._api_key = api_key.strip()
        self._username = username.strip()
        self._password = password
        self._transport = transport or UrllibTransport()
        self._clock = clock or _now
        self._request_id_factory = request_id_factory or (lambda: str(uuid.uuid4()))
        self._max_attempts = max_attempts
        self._secrets = tuple(
            item for item in (self._api_key, self._password, self._username) if item
        )

    def check(self) -> ProviderCheck:
        if (
            not self._base_url.strip()
            or not self._org_id
            or not self._username
            or not self._password
        ):
            return self._status(
                operation="auth.login",
                status="unconfigured",
                reason=(
                    "Zetaris login needs the instance URL, organization id, username, and password"
                ),
                verified=False,
            )
        self._reject_whitespace()
        if ":" in self._username:
            raise ProviderError(
                provider="zetaris",
                kind="unsupported",
                reason="username cannot contain a colon",
            )
        origin = self._origin()
        request_id = self._request_id()
        token = base64.b64encode(f"{self._username}:{self._password}".encode()).decode("ascii")
        try:
            response = send_with_budget(
                self._transport,
                HttpRequest(
                    method="GET",
                    url=f"{origin}/api/v1.0/auth/login",
                    headers={
                        "Authorization": f"Basic {token}",
                        "Accept": "application/json",
                        "X-Request-ID": request_id,
                        "X-Org-ID": self._org_id,
                    },
                    body=None,
                    timeout=ensure_timeout(
                        _TIMEOUT_CEILING, ceiling=_TIMEOUT_CEILING, provider="zetaris"
                    ),
                ),
                provider="zetaris",
                secrets=self._secrets,
                max_attempts=self._max_attempts,
            )
        except ProviderError as exc:
            if exc.kind == "offline":
                return self._status(
                    operation="auth.login",
                    status="offline",
                    reason=exc.reason,
                    verified=False,
                )
            raise
        error = failure_from_status(response, provider="zetaris", secrets=self._secrets)
        if error is not None and error.kind in {"unauthorized", "forbidden", "offline"}:
            return self._status(
                operation="auth.login",
                status=error.kind,  # type: ignore[arg-type]
                reason=error.reason,
                verified=False,
            )
        if error is not None:
            raise error
        payload = decode_object(response, provider="zetaris", secrets=self._secrets)
        identity = payload.get("idToken")
        if not isinstance(identity, str) or not identity.strip():
            raise ProviderError(
                provider="zetaris",
                kind="invalid_response",
                reason="login response did not contain an id token",
                secrets=self._secrets,
            )
        return self._status(
            operation="auth.login",
            status="available",
            reason="login was accepted; SQL access was not proven and the token was discarded",
            verified=True,
            capabilities=["auth.login"],
        )

    def query(self, statement: str, *, timeout: float = 30) -> ZetarisQueryResult:
        if not self._base_url.strip() or not self._org_id or not self._api_key:
            raise ProviderError(
                provider="zetaris",
                kind="unconfigured",
                reason="Zetaris query needs the instance URL, organization id, and API key",
            )
        self._reject_whitespace()
        sql, limit, sources = validate_read_sql(statement)
        reject_if_secret(sql, provider="zetaris", secrets=self._secrets, what="statement")
        origin = self._origin()
        request_id = self._request_id()
        response = send_with_budget(
            self._transport,
            HttpRequest(
                method="POST",
                url=f"{origin}/api/v1.0/sql-editor/sqls/run-query",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-Request-ID": request_id,
                    "X-Org-ID": self._org_id,
                },
                body=json.dumps({"sql": sql}, separators=(",", ":")).encode("utf-8"),
                timeout=ensure_timeout(timeout, ceiling=_TIMEOUT_CEILING, provider="zetaris"),
            ),
            provider="zetaris",
            secrets=self._secrets,
            max_attempts=self._max_attempts,
        )
        error = failure_from_status(response, provider="zetaris", secrets=self._secrets)
        if error is not None:
            raise error
        payload = decode_object(response, provider="zetaris", secrets=self._secrets)
        columns, rows = self._table(payload, limit=limit)
        return ZetarisQueryResult(
            queried_at=self._clock(),
            columns=columns,
            rows=rows,
            sources=sources,
            request_id=request_id,
            statement=sql,
            warnings=[
                "Zetaris rows are query provenance, not a Warden finding, and were not written",
            ],
        )

    def _table(self, payload: dict, *, limit: int) -> tuple[list[str], list[list]]:
        headers = payload.get("headers")
        data = payload.get("data")
        if not isinstance(headers, list) or not headers or not isinstance(data, list):
            raise ProviderError(
                provider="zetaris",
                kind="invalid_response",
                reason="query response did not contain headers and data",
                secrets=self._secrets,
            )
        columns: list[str] = []
        for item in headers:
            if not isinstance(item, str) or not item.strip() or item in columns:
                raise ProviderError(
                    provider="zetaris",
                    kind="invalid_response",
                    reason="query headers were not unique strings",
                    secrets=self._secrets,
                )
            reject_if_secret(item, provider="zetaris", secrets=self._secrets, what="column name")
            columns.append(item)
        if len(data) > limit:
            raise ProviderError(
                provider="zetaris",
                kind="invalid_response",
                reason="the provider returned more rows than the requested limit",
                secrets=self._secrets,
            )
        rows: list[list] = []
        for row in data:
            if not isinstance(row, list) or len(row) != len(columns):
                raise ProviderError(
                    provider="zetaris",
                    kind="invalid_response",
                    reason="a query row did not match the headers",
                    secrets=self._secrets,
                )
            values: list[str | int | float | bool | None] = []
            for value in row:
                if isinstance(value, str):
                    reject_if_secret(value, provider="zetaris", secrets=self._secrets, what="cell")
                elif value is not None and not isinstance(value, int | float | bool):
                    raise ProviderError(
                        provider="zetaris",
                        kind="invalid_response",
                        reason="a query cell was not a scalar",
                        secrets=self._secrets,
                    )
                values.append(value)
            rows.append(values)
        return columns, rows

    def _origin(self) -> str:
        try:
            return zetaris_origin(self._base_url)
        except ProviderError as exc:
            raise ProviderError(
                provider="zetaris",
                kind=exc.kind,
                reason=exc.reason,
                secrets=self._secrets,
            ) from None

    def _request_id(self) -> str:
        request_id = self._request_id_factory()
        if not isinstance(request_id, str) or not request_id.strip():
            raise ProviderError(
                provider="zetaris",
                kind="unsupported",
                reason="request id was empty",
            )
        return request_id

    def _reject_whitespace(self) -> None:
        for label, value in (
            ("organization id", self._org_id),
            ("API key", self._api_key),
            ("username", self._username),
            ("password", self._password),
        ):
            if any(character.isspace() for character in value):
                raise ProviderError(
                    provider="zetaris",
                    kind="unsupported",
                    reason=f"{label} must be a single line",
                )

    def _status(
        self,
        *,
        operation: str,
        status: str,
        reason: str,
        verified: bool,
        capabilities: list[str] | None = None,
    ) -> ProviderCheck:
        return ProviderCheck(
            provider="zetaris",
            checked_at=self._clock(),
            status=status,  # type: ignore[arg-type]
            operation=operation,
            capabilities=capabilities or [],
            reason=safe_reason(reason, self._secrets),
            verified=verified,
        )
