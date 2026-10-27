"""Synthesis flag: generation success is not H-MEM, and a check is not a deployment."""

from __future__ import annotations

from uuid import uuid4

from alaira_warden.providers.contract import ModelResult
from alaira_warden.providers.errors import ProviderError
from tests.test_product_integration import GHSA, setup_case


def _ready(product, case_id, app_id):
    client, headers = product["client"], product["headers"]
    snapshot = client.post(
        f"/api/applications/{app_id}/inventory/refresh", headers=headers, json={}
    ).json()
    run = client.post(
        f"/api/investigations/{case_id}/runs",
        headers=headers,
        json={
            "snapshot_id": snapshot["id"],
            "advisory_identifier": GHSA,
            "request_key": str(uuid4()),
        },
    ).json()
    for _ in range(3):
        response = client.post(
            f"/api/investigations/{case_id}/runs/{run['id']}/advance", headers=headers
        )
        assert response.status_code == 200, response.text
    product["client"].app.state.settings = product["settings"].model_copy(
        update={
            "warden_model_dispatch_policy": "allow_minimized",
            "warden_meterless_base_url": "http://127.0.0.1:8088/v1",
            "warden_meterless_model": "meterless/auto",
        }
    )


def test_meterless_check_does_not_mark_a_deployment(product):
    response = product["client"].post(
        "/api/integrations/meterless/check", headers=product["headers"]
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "unconfigured"
    assert body["verified"] is False
    assert body["nightshift_deployment_verified"] is False


def test_synthesis_verifies_nightshift_only_when_the_model_matches(product, monkeypatch):
    client, headers = product["client"], product["headers"]
    app_id, case_id, _fixtures = setup_case(product)
    _ready(product, case_id, app_id)

    class Matching:
        def __init__(self, **_kwargs):
            pass

        def generate_investigation(self, **kwargs):
            assert kwargs["model"] == "meterless/auto"
            return ModelResult(
                provider="meterless",
                model=kwargs["model"],
                text="Synthetic proposal",
                structured_output={"proposals": [{"statement": "Review the lockfile"}]},
            )

    monkeypatch.setattr("alaira_warden.integration.routes.MeterlessClient", Matching)
    matched = client.post(f"/api/investigations/{case_id}/synthesis", headers=headers)
    assert matched.status_code == 201, matched.text
    assert matched.json()["nightshift_deployment_verified"] is True
    assert matched.json()["engine_verified"] is True
    assert matched.json()["evidence"] is False

    class Substituted:
        def __init__(self, **_kwargs):
            pass

        def generate_investigation(self, **_kwargs):
            return ModelResult(
                provider="meterless",
                model="nvidia/nemotron",
                text="Synthetic proposal",
                structured_output={"proposals": [{"statement": "Review the lockfile"}]},
            )

    monkeypatch.setattr("alaira_warden.integration.routes.MeterlessClient", Substituted)
    other = client.post(f"/api/investigations/{case_id}/synthesis", headers=headers)
    assert other.status_code == 201, other.text
    assert other.json()["nightshift_deployment_verified"] is True
    assert other.json()["proposal"]["model"] == "nvidia/nemotron"
    assert other.json()["engine_verified"] is True


def test_synthesis_failure_does_not_verify_nightshift(product, monkeypatch):
    client, headers = product["client"], product["headers"]
    app_id, case_id, _fixtures = setup_case(product)
    _ready(product, case_id, app_id)

    class Down:
        def __init__(self, **_kwargs):
            pass

        def generate_investigation(self, **_kwargs):
            raise ProviderError(provider="meterless", kind="offline", reason="connection refused")

    monkeypatch.setattr("alaira_warden.integration.routes.MeterlessClient", Down)
    failed = client.post(f"/api/investigations/{case_id}/synthesis", headers=headers)
    assert failed.status_code == 502
    assert failed.json()["detail"]["verified"] is False
