"""Nightshift wiring with an injected transport. No live Runtime."""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from alaira_warden.nightshift import deployment_verified, healthz_url, prove_nightshift
from alaira_warden.providers.contract import ModelResult
from alaira_warden.providers.http import HttpRequest, HttpResponse, TransportFailure

_WAIT_PATH = Path(__file__).resolve().parents[2] / "infra" / "nightshift" / "wait_runtime.py"
_WAIT_SPEC = importlib.util.spec_from_file_location("nightshift_wait_runtime", _WAIT_PATH)
assert _WAIT_SPEC is not None and _WAIT_SPEC.loader is not None
_WAIT = importlib.util.module_from_spec(_WAIT_SPEC)
_WAIT_SPEC.loader.exec_module(_WAIT)
wait_for_runtime = _WAIT.wait_for_runtime

NOW = datetime(2026, 10, 27, tzinfo=UTC)
TOKEN = "nightshift-runtime-token"


class Scripted:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[HttpRequest] = []

    def send(self, request: HttpRequest) -> HttpResponse:
        self.calls.append(request)
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def response(status: int, body: object) -> HttpResponse:
    payload = body if isinstance(body, bytes) else json.dumps(body).encode()
    return HttpResponse(
        status, {"content-type": "application/json"}, payload, "http://127.0.0.1:8088"
    )


def chat(model: str, content: str = "pong") -> dict:
    return {
        "id": "req-nightshift",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}
        ],
    }


def models(ids: list[str]) -> dict:
    return {"object": "list", "data": [{"id": item} for item in ids]}


def test_healthz_url_uses_the_documented_contract():
    assert healthz_url("http://127.0.0.1:8088/v1") == "http://127.0.0.1:8088/healthz"
    assert healthz_url("http://host.docker.internal:8088/v1/") == (
        "http://host.docker.internal:8088/healthz"
    )
    with pytest.raises(ValueError):
        healthz_url("127.0.0.1:8088")


def test_deployment_flag_accepts_nightshift_resolved_models():
    ok = ModelResult(provider="meterless", model="meterless/auto", text="pong")
    routed = ModelResult(provider="meterless", model="nvidia/nemotron-3.5-bolt-e4b", text="pong")
    nvidia_direct = ModelResult(provider="nvidia", model="nvidia/nemotron", text="pong")
    assert deployment_verified(ok, "meterless/auto") is True
    assert deployment_verified(routed, "meterless/auto") is True
    assert deployment_verified(nvidia_direct, "meterless/auto") is False
    assert deployment_verified(ok, "") is False


def test_unconfigured_and_placeholder_do_not_touch_the_network():
    transport = Scripted([])
    missing = prove_nightshift(
        base_url="", api_key="", model="meterless/auto", transport=transport, clock=lambda: NOW
    )
    assert missing["status"] == "unconfigured"
    assert missing["verified"] is False
    assert missing["nightshift_deployment_verified"] is False
    placeholder = prove_nightshift(
        base_url="http://127.0.0.1:8088/v1",
        api_key="rt-local",
        model="meterless/auto",
        transport=transport,
        clock=lambda: NOW,
    )
    assert placeholder["status"] == "unauthorized"
    assert placeholder["verified"] is False
    assert transport.calls == []


def test_offline_runtime_stays_offline():
    transport = Scripted([TransportFailure("offline", "connection refused")])
    report = prove_nightshift(
        base_url="http://127.0.0.1:8088/v1",
        api_key=TOKEN,
        model="meterless/auto",
        transport=transport,
        clock=lambda: NOW,
    )
    assert report["status"] == "offline"
    assert report["verified"] is False
    assert report["status"] != "available"


def test_models_without_generation_are_not_a_deployment():
    transport = Scripted([response(200, models(["meterless/auto", "meterless/local"]))])
    report = prove_nightshift(
        base_url="http://127.0.0.1:8088/v1",
        api_key=TOKEN,
        model="meterless/auto",
        transport=transport,
        generate=False,
        clock=lambda: NOW,
    )
    assert report["models_verified"] is True
    assert report["verified"] is False
    assert report["status"] == "unproven"
    assert len(transport.calls) == 1


def test_generation_is_verified_only_when_the_runtime_echoes_the_model():
    transport = Scripted(
        [
            response(200, models(["meterless/auto"])),
            response(200, chat("meterless/auto")),
        ]
    )
    report = prove_nightshift(
        base_url="http://127.0.0.1:8088/v1",
        api_key=TOKEN,
        model="meterless/auto",
        transport=transport,
        clock=lambda: NOW,
    )
    assert report["verified"] is True
    assert report["nightshift_deployment_verified"] is True
    assert report["returned_model"] == "meterless/auto"
    assert report["nvidia_direct"] is False
    chat_call = transport.calls[1]
    assert chat_call.method == "POST"
    assert chat_call.url == "http://127.0.0.1:8088/v1/chat/completions"
    assert chat_call.headers["meterless-app"] == "alaira-warden"
    assert chat_call.headers["meterless-scope"] == "user"
    assert TOKEN not in json.dumps(report)
    body = json.loads(chat_call.body or b"{}")
    assert body["model"] == "meterless/auto"


def test_nightshift_may_resolve_auto_to_nemotron():
    transport = Scripted(
        [
            response(200, models(["meterless/auto"])),
            response(200, chat("nvidia/nemotron-3.5-bolt-e4b")),
        ]
    )
    report = prove_nightshift(
        base_url="http://127.0.0.1:8088/v1",
        api_key=TOKEN,
        model="meterless/auto",
        transport=transport,
        clock=lambda: NOW,
    )
    assert report["verified"] is True
    assert report["nightshift_deployment_verified"] is True
    assert report["returned_model"] == "nvidia/nemotron-3.5-bolt-e4b"
    assert report["nvidia_direct"] is False


def test_wait_accepts_only_healthz_200():
    calls = []

    def opener(url: str) -> int:
        calls.append(url)
        return 200 if len(calls) == 2 else 503

    ready = wait_for_runtime(
        "http://127.0.0.1:8088/v1",
        attempts=2,
        delay_seconds=0,
        opener=opener,
        sleeper=lambda _seconds: None,
    )
    assert calls == ["http://127.0.0.1:8088/healthz", "http://127.0.0.1:8088/healthz"]
    assert ready["ready"] is True
    assert ready["verified"] is False

    def down(_url: str) -> int:
        raise OSError("connection refused")

    offline = wait_for_runtime(
        "http://127.0.0.1:8088/v1",
        attempts=1,
        delay_seconds=0,
        opener=down,
        sleeper=lambda _seconds: None,
    )
    assert offline["ready"] is False
    assert offline["verified"] is False
