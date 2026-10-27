"""NVIDIA NIM chat client for the documented integrate API.

The verified operation is ``POST https://integrate.api.nvidia.com/v1/chat/completions``
with bearer authentication. The catalog index does not document ``GET /v1/models``
on this host, so a check is one bounded chat completion and is billable when the
transport is real. The caller supplies the model id. Nothing is substituted.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from alaira_warden.providers.chat import (
    authorization,
    chat_body,
    parse_chat_result,
    safe_reason,
    send_with_budget,
)
from alaira_warden.providers.contract import ModelResult, ProviderCheck
from alaira_warden.providers.errors import ProviderError
from alaira_warden.providers.http import HttpRequest, Transport, UrllibTransport, ensure_timeout
from alaira_warden.providers.structured import EvidenceRecord, validate_investigation
from alaira_warden.providers.urls import nvidia_api_base

# Descriptions on https://docs.api.nvidia.com/nim/reference/llm-apis that are not chat.
_NON_CHAT = frozenset({"nvidia/gliner-pii", "nvidia/nemoguard-jailbreak-detect"})
_DOCUMENTED_CANDIDATE = "meta/llama-3.1-8b-instruct"
_TIMEOUT_CEILING = 120.0
_INVESTIGATION_SYSTEM = (
    "Return one JSON object with the keys facts, hypotheses, references, limitations, "
    "and proposals. facts items have statement and evidence_ids. hypotheses items have "
    "statement and assumptions. proposals items have statement. references are evidence "
    "ids or URLs taken only from the evidence list. Do not add URLs, do not assign "
    "exposure, and do not call tools."
)


def _now() -> datetime:
    return datetime.now(UTC)


class NvidiaClient:
    """Direct NVIDIA API. This client does not route through Meterless."""

    documented_candidate = _DOCUMENTED_CANDIDATE

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

    def check(self, *, model: str, timeout: float) -> ProviderCheck:
        if not self._base_url.strip() or not self._api_key:
            return self._check(
                model=model or "unspecified",
                status="unconfigured",
                reason="NVIDIA base URL and API key are both required",
                verified=False,
            )
        try:
            model_id = self._model(model)
            result = self.generate_text(
                model=model_id,
                prompt="Reply with the single word pong.",
                max_output_tokens=16,
                timeout=timeout,
            )
        except ProviderError as exc:
            if exc.kind in {"unauthorized", "forbidden", "offline", "unsupported"}:
                return self._check(
                    model=model,
                    status=exc.kind,  # type: ignore[arg-type]
                    reason=exc.reason,
                    verified=False,
                )
            raise
        return self._check(
            model=result.model,
            status="available",
            reason="chat completion returned text; no separate health endpoint was called",
            verified=True,
        )

    def generate_text(
        self,
        *,
        model: str,
        prompt: str,
        max_output_tokens: int,
        timeout: float,
    ) -> ModelResult:
        if not self._base_url.strip() or not self._api_key:
            raise ProviderError(
                provider="nvidia",
                kind="unconfigured",
                reason="NVIDIA base URL and API key are both required",
            )
        model_id = self._model(model)
        if not prompt.strip():
            raise ProviderError(provider="nvidia", kind="unsupported", reason="prompt is empty")
        api_base = self._api_base()
        response = send_with_budget(
            self._transport,
            HttpRequest(
                method="POST",
                url=f"{api_base}/chat/completions",
                headers=authorization(self._api_key),
                body=chat_body(
                    model=model_id,
                    messages=[{"role": "user", "content": prompt}],
                    max_output_tokens=max_output_tokens,
                ),
                timeout=ensure_timeout(timeout, ceiling=_TIMEOUT_CEILING, provider="nvidia"),
            ),
            provider="nvidia",
            secrets=self._secrets,
            max_attempts=self._max_attempts,
        )
        return parse_chat_result(
            response,
            provider="nvidia",
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
        timeout: float,
    ) -> ModelResult:
        if not evidence:
            raise ProviderError(
                provider="nvidia",
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
                provider="nvidia",
                kind=exc.kind,
                reason=exc.reason,
                secrets=self._secrets,
            ) from None
        return result.model_copy(update={"structured_output": structured})

    def _model(self, model: str) -> str:
        if not isinstance(model, str) or not model.strip():
            raise ProviderError(
                provider="nvidia",
                kind="unsupported",
                reason="a model id is required and was not substituted",
            )
        if model in _NON_CHAT:
            raise ProviderError(
                provider="nvidia",
                kind="unsupported",
                reason="that catalog model is not a chat completion on the documented endpoint",
            )
        if len(model) > 120 or any(character.isspace() for character in model):
            raise ProviderError(
                provider="nvidia",
                kind="unsupported",
                reason="model id is not a single token",
            )
        return model

    def _api_base(self) -> str:
        try:
            return nvidia_api_base(self._base_url)
        except ProviderError as exc:
            raise ProviderError(
                provider="nvidia",
                kind=exc.kind,
                reason=exc.reason,
                secrets=self._secrets,
            ) from None

    def _check(self, *, model: str, status: str, reason: str, verified: bool) -> ProviderCheck:
        capabilities = [model] if verified and model != "unspecified" else []
        return ProviderCheck(
            provider="nvidia",
            checked_at=self._clock(),
            status=status,  # type: ignore[arg-type]
            operation="chat.completions",
            capabilities=capabilities,
            reason=safe_reason(reason, self._secrets),
            verified=verified,
        )

