"""OpenAI-compatible chat completion parsing shared by Meterless and NVIDIA.

Only a non-empty string ``content`` is accepted. Media parts and tool calls
are failures. NVIDIA must echo the requested model. Nightshift may resolve a
``meterless/*`` routing id to the backend that ran (for example Nemotron).
Missing usage stays ``None``; a schema default of zero is not invented.
"""

from __future__ import annotations

import json
from typing import Literal

from alaira_warden.providers.contract import ModelResult, Usage
from alaira_warden.providers.errors import ProviderError, redact, reject_if_secret
from alaira_warden.providers.http import (
    HttpRequest,
    HttpResponse,
    Transport,
    TransportFailure,
    ensure_attempts,
    header,
)

_PROPOSAL_WARNING = "Model output is a proposal, not technical evidence."


def optional_usage(payload: dict, *, provider: str) -> Usage | None:
    if "usage" not in payload or payload["usage"] is None:
        return None
    raw = payload["usage"]
    if not isinstance(raw, dict):
        raise ProviderError(
            provider=provider,
            kind="invalid_response",
            reason="usage was not an object",
        )

    def count(name: str) -> int | None:
        if name not in raw or raw[name] is None:
            return None
        value = raw[name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ProviderError(
                provider=provider,
                kind="invalid_response",
                reason="usage counts must be integers when present",
            )
        if value < 0:
            raise ProviderError(
                provider=provider,
                kind="invalid_response",
                reason="usage counts cannot be negative",
            )
        return value

    return Usage(
        prompt_tokens=count("prompt_tokens"),
        completion_tokens=count("completion_tokens"),
        total_tokens=count("total_tokens"),
    )


def decode_object(response: HttpResponse, *, provider: str, secrets: tuple[str, ...]) -> dict:
    content_type = header(response, "content-type").lower()
    if "text/event-stream" in content_type:
        raise ProviderError(
            provider=provider,
            kind="unsupported",
            reason="streaming responses are not accepted",
            secrets=secrets,
        )
    if content_type and "json" not in content_type:
        raise ProviderError(
            provider=provider,
            kind="invalid_response",
            reason="response content type was not JSON",
            secrets=secrets,
        )
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProviderError(
            provider=provider,
            kind="invalid_response",
            reason="response was not a JSON object",
            secrets=secrets,
        ) from None
    if not isinstance(payload, dict):
        raise ProviderError(
            provider=provider,
            kind="invalid_response",
            reason="response was not a JSON object",
            secrets=secrets,
        )
    return payload


def failure_from_status(
    response: HttpResponse,
    *,
    provider: str,
    secrets: tuple[str, ...],
) -> ProviderError | None:
    code = response.status
    if 300 <= code < 400:
        return ProviderError(
            provider=provider,
            kind="redirect_blocked",
            reason="authenticated redirect was not followed",
            secrets=secrets,
        )
    if code == 401:
        return ProviderError(
            provider=provider,
            kind="unauthorized",
            reason="authentication was rejected",
            secrets=secrets,
        )
    if code == 403:
        return ProviderError(
            provider=provider,
            kind="forbidden",
            reason="permission was denied",
            secrets=secrets,
        )
    if code == 404 or code == 422:
        return ProviderError(
            provider=provider,
            kind="unsupported",
            reason="the provider rejected the model or operation",
            secrets=secrets,
        )
    if code == 408:
        return ProviderError(
            provider=provider,
            kind="timeout",
            reason="the provider timed out",
            secrets=secrets,
        )
    if code == 429:
        return ProviderError(
            provider=provider,
            kind="rate_limited",
            reason="the provider rate limit was reached",
            secrets=secrets,
        )
    if code >= 500:
        return ProviderError(
            provider=provider,
            kind="offline",
            reason="the provider returned a server error",
            secrets=secrets,
        )
    if code != 200:
        return ProviderError(
            provider=provider,
            kind="invalid_response",
            reason="the provider returned an unexpected status",
            secrets=secrets,
        )
    return None


def send_with_budget(
    transport: Transport,
    request: HttpRequest,
    *,
    provider: str,
    secrets: tuple[str, ...],
    max_attempts: int,
) -> HttpResponse:
    attempts = ensure_attempts(max_attempts, provider=provider)
    last: HttpResponse | None = None
    for _ in range(attempts):
        try:
            last = transport.send(request)
        except TransportFailure as exc:
            raise ProviderError(
                provider=provider,
                kind="timeout" if exc.kind == "timeout" else "offline",
                reason=exc.reason,
                secrets=secrets,
            ) from None
        if last.status != 429:
            return last
    assert last is not None
    raise ProviderError(
        provider=provider,
        kind="rate_limited",
        reason="the provider rate limit was reached",
        secrets=secrets,
    )


def parse_chat_result(
    response: HttpResponse,
    *,
    provider: Literal["meterless", "nvidia"],
    requested_model: str,
    secrets: tuple[str, ...],
) -> ModelResult:
    error = failure_from_status(response, provider=provider, secrets=secrets)
    if error is not None:
        raise error
    payload = decode_object(response, provider=provider, secrets=secrets)
    if payload.get("object") not in (None, "chat.completion"):
        raise ProviderError(
            provider=provider,
            kind="invalid_response",
            reason="response object was not a chat completion",
            secrets=secrets,
        )
    returned_model = payload.get("model")
    if not isinstance(returned_model, str) or not returned_model.strip():
        raise ProviderError(
            provider=provider,
            kind="invalid_response",
            reason="response did not name a model",
            secrets=secrets,
        )
    if provider == "nvidia" and returned_model != requested_model:
        raise ProviderError(
            provider=provider,
            kind="invalid_response",
            reason="the provider returned a different model than the one requested",
            secrets=secrets,
        )
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ProviderError(
            provider=provider,
            kind="invalid_response",
            reason="response did not contain a chat choice",
            secrets=secrets,
        )
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise ProviderError(
            provider=provider,
            kind="invalid_response",
            reason="response did not contain a chat message",
            secrets=secrets,
        )
    if "tool_calls" in message or choices[0].get("finish_reason") == "tool_calls":
        raise ProviderError(
            provider=provider,
            kind="invalid_output",
            reason="the model cannot invoke tools",
            secrets=secrets,
        )
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ProviderError(
            provider=provider,
            kind="invalid_response",
            reason="response text was empty or not a string",
            secrets=secrets,
        )
    text = content.strip()
    reject_if_secret(text, provider=provider, secrets=secrets, what="response text")
    request_id = payload.get("id")
    if request_id is not None and not isinstance(request_id, str):
        raise ProviderError(
            provider=provider,
            kind="invalid_response",
            reason="response id was not a string",
            secrets=secrets,
        )
    if isinstance(request_id, str):
        reject_if_secret(request_id, provider=provider, secrets=secrets, what="response id")
    warnings = [_PROPOSAL_WARNING]
    usage = optional_usage(payload, provider=provider)
    if usage is None or (
        usage.prompt_tokens is None
        and usage.completion_tokens is None
        and usage.total_tokens is None
    ):
        warnings.append("provider did not report token usage")
    if choices[0].get("finish_reason") == "length":
        warnings.append("output stopped at the token limit")
    return ModelResult(
        provider=provider,
        model=returned_model,
        request_id=request_id,
        text=text,
        usage=usage,
        warnings=warnings,
    )


def chat_body(
    *,
    model: str,
    messages: list[dict[str, str]],
    max_output_tokens: int,
    json_object: bool = False,
) -> bytes:
    if not isinstance(max_output_tokens, int) or isinstance(max_output_tokens, bool):
        raise ProviderError(
            provider="providers",
            kind="unsupported",
            reason="max_output_tokens must be an integer from 1 to 1024",
        )
    if max_output_tokens < 1 or max_output_tokens > 1024:
        raise ProviderError(
            provider="providers",
            kind="unsupported",
            reason="max_output_tokens must be an integer from 1 to 1024",
        )
    payload: dict[str, object] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_output_tokens,
        "stream": False,
    }
    if json_object:
        payload["response_format"] = {"type": "json_object"}
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def authorization(secret: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {secret}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def safe_reason(reason: str, secrets: tuple[str, ...]) -> str:
    return redact(reason, secrets)[:300]
