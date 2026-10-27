"""Nightshift attachment helpers.

H-MEM stays the Meterless Engine. This module only talks to the host Runtime
through MeterlessClient and never calls NVIDIA.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from alaira_warden.providers.contract import ModelResult
from alaira_warden.providers.errors import ProviderError
from alaira_warden.providers.http import Transport
from alaira_warden.providers.meterless import MeterlessClient

_PROBE_PROMPT = "Reply with the single word pong."
_CHECK_STATUSES = {
    "unconfigured",
    "unauthorized",
    "forbidden",
    "offline",
    "unsupported",
    "available",
    "timeout",
    "invalid_response",
    "invalid_output",
    "rate_limited",
}


def deployment_verified(result: ModelResult, requested_model: str) -> bool:
    """True after a Nightshift generation with a named model.

    Routing ids such as ``meterless/auto`` are modes. Nightshift may resolve
    them to a cloud Nemotron id. That is still Nightshift, not NVIDIA-direct.
    """
    return bool(
        requested_model.strip()
        and result.provider == "meterless"
        and str(result.model).strip()
        and "mock" not in result.model.lower()
        and not any("synthetic_mock" in warning for warning in result.warnings)
    )


def healthz_url(base_url: str) -> str:
    """Turn a Runtime base URL into its ``/healthz`` URL. Does not invent a port."""
    value = base_url.strip().rstrip("/")
    if not value or "://" not in value:
        raise ValueError("Nightshift base URL must include a scheme and host")
    parsed = urlsplit(value)
    if not parsed.hostname:
        raise ValueError("Nightshift base URL must include a host")
    path = parsed.path
    for suffix in ("/v1/chat/completions", "/v1/models", "/healthz", "/v1"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    if path not in {"", "/"}:
        raise ValueError("Nightshift base URL path is not the documented Runtime contract")
    return urlunsplit((parsed.scheme, parsed.netloc, "/healthz", "", ""))


def prove_nightshift(
    *,
    base_url: str,
    api_key: str,
    model: str,
    transport: Transport | None = None,
    generate: bool = True,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Probe Runtime. ``verified`` is true only when a real generation echoes ``model``."""
    moment = (clock or (lambda: datetime.now(UTC)))()
    client = MeterlessClient(
        base_url=base_url,
        api_key=api_key,
        transport=transport,
        clock=lambda: moment,
    )
    report: dict[str, Any] = {
        "checked_at": moment.isoformat(),
        "verified": False,
        "nightshift_deployment_verified": False,
        "status": "unconfigured",
        "models_status": None,
        "models_verified": False,
        "operation": None,
        "requested_model": model,
        "returned_model": None,
        "reason": "Meterless base URL and token are both required",
        "engine": "hmem",
        "engine_note": "H-MEM remains the Meterless Engine. This probe does not verify memory.",
        "nvidia_direct": False,
    }
    try:
        models = client.check("models")
    except ProviderError as exc:
        report["status"] = exc.kind if exc.kind in _CHECK_STATUSES else "offline"
        report["operation"] = "models"
        report["reason"] = exc.reason
        return _without_secret(report, api_key)
    report["models_status"] = models.status
    report["models_verified"] = models.verified
    report["operation"] = "models"
    report["reason"] = models.reason
    if models.status != "available":
        report["status"] = models.status
        return _without_secret(report, api_key)
    if not generate:
        report["status"] = "unproven"
        report["reason"] = "model discovery succeeded; generation was not requested"
        return _without_secret(report, api_key)
    if not model.strip():
        report["status"] = "unproven"
        report["reason"] = "WARDEN_METERLESS_MODEL must be a meterless/* routing id"
        return _without_secret(report, api_key)
    try:
        result = client.generate_text(
            model=model,
            prompt=_PROBE_PROMPT,
            max_output_tokens=16,
            timeout=30,
        )
    except ProviderError as exc:
        report["status"] = exc.kind if exc.kind in _CHECK_STATUSES else "offline"
        report["operation"] = "chat.completions"
        report["reason"] = exc.reason
        return _without_secret(report, api_key)
    verified = deployment_verified(result, model)
    report["operation"] = "chat.completions"
    report["returned_model"] = result.model
    report["verified"] = verified
    report["nightshift_deployment_verified"] = verified
    report["status"] = "available" if verified else "unproven"
    if verified and result.model == model:
        report["reason"] = "generation succeeded and the runtime echoed the requested routing id"
    elif verified:
        report["reason"] = (
            f"generation succeeded via Nightshift; runtime resolved {model} to {result.model}"
        )
    else:
        report["reason"] = "generation did not name a usable model"
    return _without_secret(report, api_key)


def _without_secret(report: dict[str, Any], api_key: str) -> dict[str, Any]:
    secret = api_key.strip()
    if len(secret) < 8:
        return report
    encoded = json.dumps(report)
    if secret not in encoded:
        return report
    return json.loads(encoded.replace(secret, "[redacted]"))
