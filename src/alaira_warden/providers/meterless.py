"""Meterless Runtime client.

Contract implemented: Meterless Runtime 0.90.0 as published in
``docs/agent-ready/add-meterless-provider.md`` (Apache-2.0 repository).
The engines page also embeds a later prompt labeled Runtime 1.4 / contract v4.
This client implements the rules both texts share and does not implement port
auto-detection, connect-link parsing, media routes, or ``/v1/meterless/*``.

``GET /healthz`` only proves the process. ``GET /v1/models`` decides
authentication. Generation is ``POST /v1/chat/completions``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from alaira_warden.providers.chat import (
    authorization,
    chat_body,
    decode_object,
    failure_from_status,
    parse_chat_result,
    safe_reason,
    send_with_budget,
)
from alaira_warden.providers.contract import ModelResult, ProviderCheck
from alaira_warden.providers.errors import ProviderError, reject_if_secret
from alaira_warden.providers.http import HttpRequest, Transport, UrllibTransport, ensure_timeout
from alaira_warden.providers.structured import EvidenceRecord, validate_investigation
from alaira_warden.providers.urls import meterless_endpoints

_APP = "alaira-warden"
_MODEL_ID = re.compile(r"^meterless/[a-z0-9][a-z0-9._-]{0,80}$")
_PLACEHOLDER = "rt-local"
_TIMEOUT_CEILING = 180.0
_INVESTIGATION_SYSTEM = (
    "Return one JSON object with the keys facts, hypotheses, references, limitations, "
    "and proposals. facts items have statement and evidence_ids. hypotheses items have "
    "statement and assumptions. proposals items have statement. references are evidence "
    "ids or URLs taken only from the evidence list. Do not add URLs, do not assign "
    "exposure, and do not call tools."
)


def _now() -> datetime:
    return datetime.now(UTC)


class MeterlessClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        transport: Transport | None = None,
        clock: Callable[[], datetime] | None = None,
        max_attempts: int = 1,
    ):
        self._base_url = base_url
        self._api_key = api_key.strip()
        self._transport = transport or UrllibTransport()
        self._clock = clock or _now
        self._max_attempts = max_attempts
        self._secrets = (self._api_key,) if self._api_key else ()

    def check(self, operation: Literal["health", "models"] = "models") -> ProviderCheck:
        if operation not in {"health", "models"}:
            raise ProviderError(
                provider="meterless",
                kind="unsupported",
                reason="Meterless check only supports health and models",
            )
        if not self._base_url.strip() or not self._api_key:
            return self._check(
                operation=operation,
                status="unconfigured",
                capabilities=[],
                reason="Meterless base URL and token are both required",
                verified=False,
            )
        if self._api_key == _PLACEHOLDER:
            return self._check(
                operation=operation,
                status="unauthorized",
                capabilities=[],
                reason="the published rt-local placeholder token is rejected",
                verified=False,
            )
        origin, api_base = self._endpoints()
        if operation == "health":
            url = f"{origin}/healthz"
        else:
            url = f"{api_base}/models"
        try:
            response = send_with_budget(
                self._transport,
                HttpRequest(
                    method="GET",
                    url=url,
                    headers=self._headers(chat=False),
                    body=None,
                    timeout=ensure_timeout(
                        _TIMEOUT_CEILING, ceiling=_TIMEOUT_CEILING, provider="meterless"
                    ),
                ),
                provider="meterless",
                secrets=self._secrets,
                max_attempts=self._max_attempts,
            )
        except ProviderError as exc:
            if exc.kind == "offline":
                return self._check(
                    operation=operation,
                    status="offline",
                    capabilities=[],
                    reason=exc.reason,
                    verified=False,
                )
            raise
        error = failure_from_status(response, provider="meterless", secrets=self._secrets)
        if error is not None and error.kind in {"unauthorized", "forbidden", "offline"}:
            return self._check(
                operation=operation,
                status=error.kind,  # type: ignore[arg-type]
                capabilities=[],
                reason=error.reason,
                verified=False,
            )
        if error is not None:
            raise error
        if operation == "health":
            return self._check(
                operation="health",
                status="available",
                capabilities=["process"],
                reason="process responded; authentication and generation were not proven",
                verified=True,
            )
        payload = decode_object(response, provider="meterless", secrets=self._secrets)
        return self._models_check(payload)

    def generate_text(
        self,
        *,
        model: str,
        prompt: str,
        max_output_tokens: int,
        timeout: float = _TIMEOUT_CEILING,
    ) -> ModelResult:
        self._require_configured()
        model_id = self._model(model)
        if not prompt.strip():
            raise ProviderError(provider="meterless", kind="unsupported", reason="prompt is empty")
        _, api_base = self._endpoints()
        response = send_with_budget(
            self._transport,
            HttpRequest(
                method="POST",
                url=f"{api_base}/chat/completions",
                headers=self._headers(chat=True),
                body=chat_body(
                    model=model_id,
                    messages=[{"role": "user", "content": prompt}],
                    max_output_tokens=max_output_tokens,
                ),
                timeout=ensure_timeout(timeout, ceiling=_TIMEOUT_CEILING, provider="meterless"),
            ),
            provider="meterless",
            secrets=self._secrets,
            max_attempts=self._max_attempts,
        )
        return parse_chat_result(
            response,
            provider="meterless",
            requested_model=model_id,
            secrets=self._secrets,
        )

    def generate_investigation(
        self,
        *,
        model: str,
        task: str,
        evidence: list[EvidenceRecord],
        max_output_tokens: int,
        timeout: float = _TIMEOUT_CEILING,
    ) -> ModelResult:
        if not evidence:
            raise ProviderError(
                provider="meterless",
                kind="unsupported",
                reason="investigation requires at least one evidence record",
            )
        evidence_payload = [item.model_dump() for item in evidence]
        prompt = (
            f"{_INVESTIGATION_SYSTEM}\n"
            f"Evidence: {evidence_payload}\n"
            f"Task: {task.strip()}"
        )
        result = self.generate_text(
            model=model,
            prompt=prompt,
            max_output_tokens=max_output_tokens,
            timeout=timeout,
        )
        try:
            structured = validate_investigation(result.text, evidence)
        except ProviderError as exc:
            raise ProviderError(
                provider="meterless",
                kind=exc.kind,
                reason=exc.reason,
                secrets=self._secrets,
            ) from None
        return result.model_copy(update={"structured_output": structured})

    def _models_check(self, payload: dict) -> ProviderCheck:
        data = payload.get("data")
        if not isinstance(data, list):
            raise ProviderError(
                provider="meterless",
                kind="invalid_response",
                reason="model list did not contain data",
                secrets=self._secrets,
            )
        identifiers: list[str] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            identifier = item.get("id")
            if not isinstance(identifier, str) or not _MODEL_ID.fullmatch(identifier):
                continue
            reject_if_secret(
                identifier,
                provider="meterless",
                secrets=self._secrets,
                what="model id",
            )
            identifiers.append(identifier)
        if not identifiers:
            return self._check(
                operation="models",
                status="unsupported",
                capabilities=[],
                reason="model list did not include meterless routing modes",
                verified=False,
            )
        return self._check(
            operation="models",
            status="available",
            capabilities=identifiers,
            reason="model discovery succeeded; generation was not proven",
            verified=True,
        )

    def _require_configured(self) -> None:
        if not self._base_url.strip() or not self._api_key:
            raise ProviderError(
                provider="meterless",
                kind="unconfigured",
                reason="Meterless base URL and token are both required",
            )
        if self._api_key == _PLACEHOLDER:
            raise ProviderError(
                provider="meterless",
                kind="unauthorized",
                reason="the published rt-local placeholder token is rejected",
            )

    def _endpoints(self) -> tuple[str, str]:
        try:
            return meterless_endpoints(self._base_url)
        except ProviderError as exc:
            raise ProviderError(
                provider="meterless",
                kind=exc.kind,
                reason=exc.reason,
                secrets=self._secrets,
            ) from None

    def _model(self, model: str) -> str:
        if not _MODEL_ID.fullmatch(model):
            raise ProviderError(
                provider="meterless",
                kind="unsupported",
                reason="model id must be a meterless routing mode; it was not replaced",
            )
        return model

    def _headers(self, *, chat: bool) -> dict[str, str]:
        headers = authorization(self._api_key)
        headers["meterless-app"] = _APP
        if chat:
            headers["meterless-scope"] = "user"
        return headers

    def _check(
        self,
        *,
        operation: str,
        status: str,
        capabilities: list[str],
        reason: str,
        verified: bool,
    ) -> ProviderCheck:
        return ProviderCheck(
            provider="meterless",
            checked_at=self._clock(),
            status=status,  # type: ignore[arg-type]
            operation=operation,
            capabilities=capabilities,
            reason=safe_reason(reason, self._secrets),
            verified=verified,
        )
