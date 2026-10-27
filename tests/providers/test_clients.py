"""Offline contract tests for Meterless, NVIDIA, and Zetaris clients."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from alaira_warden.providers.chat import chat_body
from alaira_warden.providers.contract import ProviderCheck
from alaira_warden.providers.errors import ProviderError
from alaira_warden.providers.http import (
    HttpRequest,
    HttpResponse,
    TransportFailure,
    UrllibTransport,
)
from alaira_warden.providers.meterless import MeterlessClient
from alaira_warden.providers.nvidia import NvidiaClient
from alaira_warden.providers.structured import EvidenceRecord
from alaira_warden.providers.urls import meterless_endpoints, nvidia_api_base, zetaris_origin
from alaira_warden.providers.zetaris import ZetarisClient

NOW = datetime(2026, 10, 26, tzinfo=UTC)
METERLESS_SECRET = "meterless-token-value"
NVIDIA_SECRET = "nvidia-token-value"
ZETARIS_KEY = "zetaris-api-key-value"
ZETARIS_PASSWORD = "zetaris-password-value"
NVIDIA_BASE = "https://integrate.api.nvidia.com/v1"
MODEL = "meta/llama-3.1-8b-instruct"
EVIDENCE = [EvidenceRecord(id="e1", url="https://example.com/advisory")]


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


def response(status: int, body: object, *, content_type: str = "application/json") -> HttpResponse:
    if isinstance(body, bytes):
        payload = body
    elif isinstance(body, str):
        payload = body.encode()
    else:
        payload = json.dumps(body).encode()
    return HttpResponse(status, {"content-type": content_type}, payload, "https://example.test")


def chat(content: str, *, model: str, usage: dict | None = None, extra: dict | None = None) -> dict:
    message = {"role": "assistant", "content": content}
    if extra:
        message.update(extra)
    payload = {
        "id": "req-1",
        "object": "chat.completion",
        "model": model,
        "choices": [{"message": message, "finish_reason": "stop"}],
    }
    if usage is not None:
        payload["usage"] = usage
    return payload


def meterless(transport: Scripted, **kwargs) -> MeterlessClient:
    return MeterlessClient(
        base_url="http://127.0.0.1:8088/v1",
        api_key=METERLESS_SECRET,
        transport=transport,
        clock=lambda: NOW,
        **kwargs,
    )


def nvidia(transport: Scripted, **kwargs) -> NvidiaClient:
    return NvidiaClient(
        base_url=NVIDIA_BASE,
        api_key=NVIDIA_SECRET,
        transport=transport,
        clock=lambda: NOW,
        **kwargs,
    )


def zetaris(transport: Scripted, **kwargs) -> ZetarisClient:
    values = {
        "base_url": "https://zetaris.example",
        "org_id": "7",
        "api_key": ZETARIS_KEY,
        "username": "analyst",
        "password": ZETARIS_PASSWORD,
        "transport": transport,
        "clock": lambda: NOW,
        "request_id_factory": lambda: "req-fixed",
    }
    values.update(kwargs)
    return ZetarisClient(**values)


def assert_clean(text: str) -> None:
    for secret in (METERLESS_SECRET, NVIDIA_SECRET, ZETARIS_KEY, ZETARIS_PASSWORD):
        assert secret not in text


def test_urls_normalize_once_and_reject_embedded_credentials():
    origin, api = meterless_endpoints("127.0.0.1:8088/v1/chat/completions")
    assert origin == "http://127.0.0.1:8088"
    assert api == "http://127.0.0.1:8088/v1"
    assert meterless_endpoints("http://127.0.0.1:8088/v1/v1")[1] == "http://127.0.0.1:8088/v1"
    assert meterless_endpoints("http://[::1]:8088/healthz")[1] == "http://[::1]:8088/v1"
    assert nvidia_api_base("https://integrate.api.nvidia.com/v1/chat/completions") == NVIDIA_BASE
    assert zetaris_origin("https://zetaris.example/api/v1.0/auth/login") == "https://zetaris.example"
    with pytest.raises(ProviderError, match="embedded credentials") as exc:
        meterless_endpoints("http://user:meterless-token-value@127.0.0.1:8088/v1")
    assert_clean(str(exc.value))
    with pytest.raises(ProviderError, match="embedded credentials") as exc:
        meterless_endpoints("http://127.0.0.1:8088/connect#k=meterless-token-value")
    assert_clean(str(exc.value))


def test_meterless_connection_states_are_distinct():
    missing = MeterlessClient(base_url="", api_key="", transport=Scripted([]), clock=lambda: NOW)
    assert missing.check().status == "unconfigured"
    assert missing.check().verified is False

    placeholder = MeterlessClient(
        base_url="http://127.0.0.1:8088/v1",
        api_key="rt-local",
        transport=Scripted([]),
        clock=lambda: NOW,
    )
    refused = placeholder.check()
    assert refused.status == "unauthorized"
    assert placeholder._transport.calls == []  # type: ignore[attr-defined]

    unauthorized = Scripted([response(401, {"error": METERLESS_SECRET})])
    assert meterless(unauthorized).check().status == "unauthorized"
    forbidden = Scripted([response(403, "denied")])
    assert meterless(forbidden).check().status == "forbidden"
    down = Scripted([TransportFailure("offline", "provider unreachable")])
    assert meterless(down).check().status == "offline"
    assert {refused.status, "unauthorized", "forbidden", "offline"} >= {
        "unauthorized",
        "forbidden",
        "offline",
    }


def test_meterless_health_does_not_prove_models_or_generation():
    transport = Scripted([response(200, "ok", content_type="text/plain")])
    result = meterless(transport).check(operation="health")
    assert result.status == "available"
    assert result.operation == "health"
    assert result.capabilities == ["process"]
    assert result.verified is True
    assert transport.calls[0].url == "http://127.0.0.1:8088/healthz"
    assert "meterless-scope" not in transport.calls[0].headers
    assert transport.calls[0].headers["meterless-app"] == "alaira-warden"
    assert transport.calls[0].headers["Authorization"] == f"Bearer {METERLESS_SECRET}"


def test_meterless_models_require_routing_ids_and_keep_unknown_modes():
    payload = {"data": [{"id": "meterless/auto"}, {"id": "meterless/text.fast"}, {"id": "other"}]}
    transport = Scripted([response(200, payload)])
    result = meterless(transport).check(operation="models")
    assert result.status == "available"
    assert result.capabilities == ["meterless/auto", "meterless/text.fast"]
    assert "generation" not in result.capabilities
    empty = Scripted([response(200, {"data": [{"id": "gpt-4"}]})])
    unsupported = meterless(empty).check()
    assert unsupported.status == "unsupported"
    assert unsupported.verified is False


def test_meterless_generation_keeps_usage_and_rejects_substitution():
    transport = Scripted(
        [
            response(
                200,
                chat(
                    "pong",
                    model="meterless/auto",
                    usage={"prompt_tokens": 0, "completion_tokens": 1, "total_tokens": 1},
                ),
            )
        ]
    )
    result = meterless(transport).generate_text(
        model="meterless/auto",
        prompt="Reply with pong.",
        max_output_tokens=16,
        timeout=5,
    )
    assert result.text == "pong"
    assert result.usage is not None
    assert result.usage.prompt_tokens == 0
    body = json.loads(transport.calls[0].body.decode())
    assert body["model"] == "meterless/auto"
    assert body["max_tokens"] == 16
    assert body["stream"] is False
    assert "tools" not in body
    assert transport.calls[0].headers["meterless-scope"] == "user"

    swapped = Scripted([response(200, chat("pong", model="meterless/fast"))])
    with pytest.raises(ProviderError, match="different model") as exc:
        meterless(swapped).generate_text(
            model="meterless/auto", prompt="Reply with pong.", max_output_tokens=16, timeout=5
        )
    assert len(swapped.calls) == 1
    assert json.loads(swapped.calls[0].body.decode())["model"] == "meterless/auto"
    assert_clean(str(exc.value))

    with pytest.raises(ProviderError, match="not replaced") as exc:
        meterless(Scripted([])).generate_text(
            model="meta/llama-3.1-8b-instruct",
            prompt="Reply with pong.",
            max_output_tokens=16,
            timeout=5,
        )
    assert exc.value.kind == "unsupported"


def test_budget_timeout_redirect_and_invalid_json_stay_finite():
    limited = Scripted([response(429, {"error": METERLESS_SECRET}) for _ in range(3)])
    with pytest.raises(ProviderError) as exc:
        meterless(limited, max_attempts=3).generate_text(
            model="meterless/auto", prompt="Reply with pong.", max_output_tokens=16, timeout=5
        )
    assert exc.value.kind == "rate_limited"
    assert len(limited.calls) == 3
    assert_clean(str(exc.value))

    crashed = Scripted([response(500, METERLESS_SECRET), response(500, "again")])
    with pytest.raises(ProviderError) as exc:
        meterless(crashed, max_attempts=3).generate_text(
            model="meterless/auto", prompt="Reply with pong.", max_output_tokens=16, timeout=5
        )
    assert exc.value.kind == "offline"
    assert len(crashed.calls) == 1

    timed = Scripted([TransportFailure("timeout", "request timed out")])
    with pytest.raises(ProviderError) as exc:
        meterless(timed, max_attempts=3).check()
    assert exc.value.kind == "timeout"
    assert len(timed.calls) == 1

    redirected = Scripted(
        [response(302, "", content_type="text/plain")]
    )
    with pytest.raises(ProviderError) as exc:
        meterless(redirected).generate_text(
            model="meterless/auto", prompt="Reply with pong.", max_output_tokens=16, timeout=5
        )
    assert exc.value.kind == "redirect_blocked"
    assert len(redirected.calls) == 1

    broken = Scripted([response(200, f"not-json {METERLESS_SECRET}")])
    with pytest.raises(ProviderError) as exc:
        meterless(broken).generate_text(
            model="meterless/auto", prompt="Reply with pong.", max_output_tokens=16, timeout=5
        )
    assert exc.value.kind == "invalid_response"
    assert_clean(str(exc.value))

    with pytest.raises(ProviderError):
        meterless(Scripted([])).generate_text(
            model="meterless/auto", prompt="Reply with pong.", max_output_tokens=0, timeout=5
        )
    with pytest.raises(ProviderError):
        meterless(Scripted([]), max_attempts=4).generate_text(
            model="meterless/auto", prompt="Reply with pong.", max_output_tokens=16, timeout=5
        )


def test_missing_usage_is_not_zero_and_empty_text_is_not_success():
    transport = Scripted([response(200, chat("pong", model="meterless/auto"))])
    result = meterless(transport).generate_text(
        model="meterless/auto", prompt="Reply with pong.", max_output_tokens=16, timeout=5
    )
    assert result.usage is None
    assert any("did not report token usage" in warning for warning in result.warnings)
    empty = Scripted([response(200, chat("  ", model="meterless/auto"))])
    with pytest.raises(ProviderError) as exc:
        meterless(empty).generate_text(
            model="meterless/auto", prompt="Reply with pong.", max_output_tokens=16, timeout=5
        )
    assert exc.value.kind == "invalid_response"


def test_structured_output_rejects_foreign_references_exposure_and_tools():
    good = {
        "facts": [{"statement": "The advisory names package demo.", "evidence_ids": ["e1"]}],
        "hypotheses": [{"statement": "The installed version may differ.", "assumptions": []}],
        "references": ["e1"],
        "limitations": ["No deployment record was provided."],
        "proposals": [{"statement": "Compare the lockfile with evidence e1."}],
    }
    transport = Scripted([response(200, chat(json.dumps(good), model="meterless/auto"))])
    result = meterless(transport).generate_investigation(
        model="meterless/auto",
        task="Summarize the synthetic advisory.",
        evidence=EVIDENCE,
        max_output_tokens=200,
        timeout=5,
    )
    assert result.structured_output["references"] == ["e1"]
    assert result.usage is None
    assert "exposure" not in result.structured_output

    foreign = dict(good, references=["https://evil.example/advisory"])
    bad = Scripted([response(200, chat(json.dumps(foreign), model="meterless/auto"))])
    with pytest.raises(ProviderError) as exc:
        meterless(bad).generate_investigation(
            model="meterless/auto",
            task="Summarize.",
            evidence=EVIDENCE,
            max_output_tokens=200,
            timeout=5,
        )
    assert exc.value.kind == "invalid_output"
    assert "not in the provided evidence" in exc.value.reason

    invented = {
        **good,
        "facts": [
            {
                "statement": "See https://evil.example/advisory for the exploit.",
                "evidence_ids": ["e1"],
            }
        ],
    }
    with pytest.raises(ProviderError, match="not in the provided evidence"):
        meterless(
            Scripted([response(200, chat(json.dumps(invented), model="meterless/auto"))])
        ).generate_investigation(
            model="meterless/auto",
            task="Summarize.",
            evidence=EVIDENCE,
            max_output_tokens=200,
            timeout=5,
        )

    exposed = dict(good, exposure="confirmed")
    with pytest.raises(ProviderError, match="cannot assign exposure"):
        meterless(
            Scripted([response(200, chat(json.dumps(exposed), model="meterless/auto"))])
        ).generate_investigation(
            model="meterless/auto",
            task="Summarize.",
            evidence=EVIDENCE,
            max_output_tokens=200,
            timeout=5,
        )

    verdict = {
        **good,
        "proposals": [{"statement": "This is confirmed exposure of the service."}],
    }
    with pytest.raises(ProviderError, match="definitive exposure"):
        meterless(
            Scripted([response(200, chat(json.dumps(verdict), model="meterless/auto"))])
        ).generate_investigation(
            model="meterless/auto",
            task="Summarize.",
            evidence=EVIDENCE,
            max_output_tokens=200,
            timeout=5,
        )

    with pytest.raises(ProviderError, match="not the expected JSON"):
        client = meterless(Scripted([response(200, chat("not json", model="meterless/auto"))]))
        client.generate_investigation(
            model="meterless/auto",
            task="Summarize.",
            evidence=EVIDENCE,
            max_output_tokens=200,
            timeout=5,
        )

    tools = chat("", model="meterless/auto", extra={"tool_calls": [{"id": "1"}]})
    with pytest.raises(ProviderError, match="cannot invoke tools"):
        meterless(Scripted([response(200, tools)])).generate_text(
            model="meterless/auto", prompt="Reply with pong.", max_output_tokens=16, timeout=5
        )


def test_provider_headers_do_not_cross_hosts():
    shared = Scripted(
        [
            response(200, {"data": [{"id": "meterless/auto"}]}),
            response(
                200,
                chat("pong", model=MODEL, usage={"prompt_tokens": 2, "completion_tokens": 1}),
            ),
        ]
    )
    meterless(shared).check(operation="models")
    nvidia(shared).generate_text(
        model=MODEL, prompt="Reply with pong.", max_output_tokens=16, timeout=5
    )
    meterless_call, nvidia_call = shared.calls
    assert meterless_call.url.startswith("http://127.0.0.1:8088/")
    assert nvidia_call.url == "https://integrate.api.nvidia.com/v1/chat/completions"
    assert METERLESS_SECRET not in nvidia_call.headers["Authorization"]
    assert NVIDIA_SECRET not in meterless_call.headers["Authorization"]
    assert "meterless-app" not in nvidia_call.headers
    assert "X-Org-ID" not in nvidia_call.headers
    assert nvidia_call.headers["Authorization"] == f"Bearer {NVIDIA_SECRET}"


def test_nvidia_states_and_no_silent_model_substitution():
    missing = NvidiaClient(base_url="", api_key="", transport=Scripted([]), clock=lambda: NOW)
    assert missing.check(model=MODEL, timeout=5).status == "unconfigured"

    unauthorized = Scripted([response(401, {"detail": NVIDIA_SECRET})])
    assert nvidia(unauthorized).check(model=MODEL, timeout=5).status == "unauthorized"
    forbidden = Scripted([response(403, "no")])
    assert nvidia(forbidden).check(model=MODEL, timeout=5).status == "forbidden"
    down = Scripted([TransportFailure("offline", "provider unreachable")])
    assert nvidia(down).check(model=MODEL, timeout=5).status == "offline"

    wrong_host = NvidiaClient(
        base_url="http://127.0.0.1:8088/v1",
        api_key=NVIDIA_SECRET,
        transport=Scripted([]),
        clock=lambda: NOW,
    )
    refused = wrong_host.check(model=MODEL, timeout=5)
    assert refused.status == "unsupported"
    assert wrong_host._transport.calls == []  # type: ignore[attr-defined]
    assert_clean(refused.reason)

    non_chat = Scripted([])
    result = nvidia(non_chat).check(model="nvidia/gliner-pii", timeout=5)
    assert result.status == "unsupported"
    assert non_chat.calls == []

    rejected = Scripted([response(422, {"detail": "unknown model"})])
    with pytest.raises(ProviderError) as exc:
        nvidia(rejected).generate_text(
            model="some-other-model", prompt="Reply with pong.", max_output_tokens=16, timeout=5
        )
    assert exc.value.kind == "unsupported"
    assert len(rejected.calls) == 1
    assert json.loads(rejected.calls[0].body.decode())["model"] == "some-other-model"

    partial = Scripted(
        [response(200, chat("pong", model=MODEL, usage={"prompt_tokens": 4}))]
    )
    generated = nvidia(partial).generate_text(
        model=MODEL, prompt="Reply with pong.", max_output_tokens=16, timeout=5
    )
    assert generated.usage is not None
    assert generated.usage.prompt_tokens == 4
    assert generated.usage.completion_tokens is None
    assert generated.usage.total_tokens is None


def test_zetaris_login_and_bounded_read_keep_provenance():
    missing = ZetarisClient(
        base_url="",
        org_id="",
        transport=Scripted([]),
        clock=lambda: NOW,
    )
    assert missing.check().status == "unconfigured"

    login = Scripted(
        [
            response(401, {"message": ZETARIS_PASSWORD}),
            response(403, "denied"),
            TransportFailure("offline", "provider unreachable"),
            response(200, {"idToken": "id-token-value", "refreshToken": "refresh-token-value"}),
        ]
    )
    client = zetaris(login)
    assert client.check().status == "unauthorized"
    assert client.check().status == "forbidden"
    assert client.check().status == "offline"
    accepted = client.check()
    assert isinstance(accepted, ProviderCheck)
    assert accepted.status == "available"
    assert accepted.operation == "auth.login"
    assert accepted.verified is True
    dumped = accepted.model_dump_json()
    assert "id-token-value" not in dumped
    assert "refresh-token-value" not in dumped
    assert_clean(dumped)
    assert login.calls[0].url == "https://zetaris.example/api/v1.0/auth/login"
    assert login.calls[0].headers["Authorization"].startswith("Basic ")
    assert ZETARIS_KEY not in login.calls[0].headers["Authorization"]
    assert login.calls[0].headers["X-Org-ID"] == "7"

    query_transport = Scripted(
        [response(200, {"headers": ["id", "name"], "data": [[1, "synthetic"]]})]
    )
    result = zetaris(query_transport).query("SELECT id, name FROM synthetic.events LIMIT 2")
    assert result.columns == ["id", "name"]
    assert result.rows == [[1, "synthetic"]]
    assert result.sources == ["synthetic.events"]
    assert result.request_id == "req-fixed"
    assert result.queried_at == NOW
    sent = query_transport.calls[0]
    assert sent.url == "https://zetaris.example/api/v1.0/sql-editor/sqls/run-query"
    assert sent.headers["Authorization"] == f"Bearer {ZETARIS_KEY}"
    assert not sent.headers["Authorization"].startswith("Basic ")
    assert ZETARIS_PASSWORD not in sent.headers["Authorization"]
    assert json.loads(sent.body.decode()) == {
        "sql": "SELECT id, name FROM synthetic.events LIMIT 2"
    }
    assert "finding" in result.warnings[0].lower() or "not a Warden finding" in result.warnings[0]

    blocked = Scripted([])
    for statement in (
        "DELETE FROM synthetic.events",
        "SELECT id FROM synthetic.events",
        "SELECT id FROM synthetic.events LIMIT 1000",
        "SELECT id FROM synthetic.events LIMIT 1; DROP TABLE synthetic.events",
    ):
        with pytest.raises(ProviderError) as exc:
            zetaris(blocked).query(statement)
        assert exc.value.kind == "unsupported"
    assert blocked.calls == []

    overflow = Scripted([response(200, {"headers": ["id"], "data": [[1], [2], [3]]})])
    with pytest.raises(ProviderError) as exc:
        zetaris(overflow).query("SELECT id FROM synthetic.events LIMIT 2")
    assert exc.value.kind == "invalid_response"

    denied = Scripted([response(403, {"message": ZETARIS_KEY})])
    with pytest.raises(ProviderError) as exc:
        zetaris(denied).query("SELECT id FROM synthetic.events LIMIT 1")
    assert exc.value.kind == "forbidden"
    assert_clean(str(exc.value))


def test_stdlib_transport_does_not_follow_redirects():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler name
            self.send_response(302)
            self.send_header("Location", "https://integrate.api.nvidia.com/v1/models")
            self.end_headers()

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        result = UrllibTransport().send(
            HttpRequest(
                method="GET",
                url=f"http://127.0.0.1:{port}/healthz",
                headers={"Authorization": f"Bearer {METERLESS_SECRET}"},
                body=None,
                timeout=5,
            )
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
    assert result.status == 302
    assert result.headers["location"] == "https://integrate.api.nvidia.com/v1/models"


def test_chat_body_has_a_finite_token_budget():
    encoded = chat_body(
        model="meterless/auto",
        messages=[{"role": "user", "content": "ping"}],
        max_output_tokens=32,
    )
    assert json.loads(encoded)["max_tokens"] == 32
    with pytest.raises(ProviderError):
        chat_body(model="meterless/auto", messages=[], max_output_tokens=1025)
