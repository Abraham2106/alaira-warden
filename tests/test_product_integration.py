import json
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import pytest

from alaira_warden.integration.critique import run_planner_evaluator
from alaira_warden.integration.data import CaseData
from alaira_warden.integration.routes import get_services
from alaira_warden.integration.services import ProductServices
from alaira_warden.intelligence.http import HttpResponse
from alaira_warden.orchestration.runtime import StageContext
from alaira_warden.providers.contract import ModelResult
from alaira_warden.providers.errors import ProviderError

GHSA = "GHSA-35jh-r3h4-6jhm"
CVE = "CVE-2020-8203"
SHA = "a" * 40


class PublicFixtures:
    """Controlled source responses; never opens a socket or pretends to be a live probe."""

    def __init__(self):
        self.calls = []
        self.package = {
            "name": "synthetic",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4.17.0"},
        }
        self.lock = {
            "name": "synthetic",
            "lockfileVersion": 3,
            "packages": {
                "": self.package,
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "integrity": "sha512-fixture",
                },
            },
        }

    def send(self, request):
        self.calls.append(request.url)
        path = urlsplit(request.url).path
        status = 200
        if "/commits/" in path:
            payload = {"sha": SHA}
        elif "/git/trees/" in path:
            payload = {
                "truncated": False,
                "tree": [
                    {"path": "package.json", "type": "blob", "mode": "100644", "sha": "b" * 40},
                    {
                        "path": "package-lock.json",
                        "type": "blob",
                        "mode": "100644",
                        "sha": "c" * 40,
                    },
                ],
            }
        elif path.endswith("b" * 40):
            payload = self.package
        elif path.endswith("c" * 40):
            payload = self.lock
        elif path == f"/advisories/{GHSA}":
            payload = {
                "ghsa_id": GHSA,
                "cve_id": CVE,
                "type": "reviewed",
                "summary": "Synthetic fixture",
                "description": "Controlled evidence",
                "html_url": f"https://github.com/advisories/{GHSA}",
                "published_at": "2020-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "npm", "name": "lodash"},
                        "vulnerable_version_range": "<4.17.21",
                    }
                ],
            }
        elif "api.osv.dev" in request.url:
            payload = {
                "id": GHSA,
                "modified": "2026-01-01T00:00:00Z",
                "aliases": [CVE],
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "lodash"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                            }
                        ],
                    }
                ],
            }
        elif "services.nvd.nist.gov" in request.url:
            payload = {
                "totalResults": 1,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": CVE,
                            "vulnStatus": "Analyzed",
                            "descriptions": [{"lang": "en", "value": "Fixture"}],
                        }
                    }
                ],
            }
        elif "cisa.gov" in request.url:
            payload = {
                "catalogVersion": "2026.10.27",
                "dateReleased": "2026-10-27T00:00:00Z",
                "count": 0,
                "vulnerabilities": [],
            }
        else:
            raise AssertionError(f"Unexpected fixture request {request.url}")
        return HttpResponse(status, {}, json.dumps(payload).encode())


def setup_case(product):
    client, headers = product["client"], product["headers"]
    app = client.post(
        "/api/applications",
        headers=headers,
        json={
            "name": "Integration fixture",
            "repository": "test-owner/test-repository",
            "owner": "Test team",
            "criticality": "high",
            "environments": ["production"],
        },
    )
    assert app.status_code == 201, app.text
    app_id = app.json()["id"]
    case = client.post(
        "/api/investigations",
        headers=headers,
        json={
            "application_id": app_id,
            "title": "Controlled integration case",
            "description": "Synthetic dataset",
            "source_url": f"https://github.com/advisories/{GHSA}",
        },
    )
    assert case.status_code == 201, case.text
    fixtures = PublicFixtures()
    services = ProductServices(product["settings"], transport=fixtures)
    client.app.dependency_overrides[get_services] = lambda: services
    return app_id, case.json()["id"], fixtures


def test_authenticated_inventory_sources_correlation_and_review_roundtrip(product):
    client, headers = product["client"], product["headers"]
    app_id, case_id, fixtures = setup_case(product)
    inventory = client.post(
        f"/api/applications/{app_id}/inventory/refresh", headers=headers, json={}
    )
    assert inventory.status_code == 201, inventory.text
    snapshot = inventory.json()
    assert snapshot["commit_sha"] == SHA
    assert snapshot["components"][0]["resolved_version"] == "4.17.20"

    def run():
        payload = {
            "request_key": str(uuid4()),
            "snapshot_id": snapshot["id"],
            "advisory_identifier": GHSA,
        }
        response = client.post(f"/api/investigations/{case_id}/runs", headers=headers, json=payload)
        assert response.status_code == 201, response.text
        assert (
            client.post(
                f"/api/investigations/{case_id}/runs", headers=headers, json=payload
            ).json()["id"]
            == response.json()["id"]
        )
        path = f"/api/investigations/{case_id}/runs/{response.json()['id']}/advance"
        for _ in range(3):
            result = client.post(path, headers=headers)
            assert result.status_code == 200, result.text
        assert result.json()["status"] == "awaiting_review", result.text
        return client.get(f"/api/investigations/{case_id}/context", headers=headers).json()

    first = run()
    assert first["assessments"]
    assert first["memory"]
    assert first["memory"]["engine"] == "hmem"
    assert first["memory"]["available"] is True
    assert first["memory"]["memories"]
    assert {a["payload"]["exposure"] for a in first["assessments"]} == {"undetermined"}
    assert any(
        a["payload"]["findings"][0]["version_affected"] is True for a in first["assessments"]
    )
    assert first["sponsor_data_layer_verified"] is False
    assert first["critiques"]
    assert first["critiques"][0]["payload"]["changed_exposure"] is False
    for evidence in first["evidence"]:
        if evidence["source"] in {"github", "osv"}:
            response = client.post(
                f"/api/investigations/{case_id}/evidence/{evidence['advisory_revision_id']}/review",
                headers=headers,
                json={
                    "confidence": "confirmed",
                    "justification": "Synthetic review of the controlled test fixture.",
                },
            )
            assert response.status_code == 201, response.text
    second = run()
    assert any(a["payload"]["exposure"] == "potential" for a in second["assessments"])
    assert all(
        f["compromise"] == "unknown"
        for a in second["assessments"]
        for f in a["payload"]["findings"]
    )
    assert any("cisa.gov" in url for url in fixtures.calls)
    with product["connect"](product["settings"]) as connection:
        actors = connection.execute(
            "SELECT DISTINCT actor FROM audit_events WHERE entity_id IN (%s,%s)", (app_id, case_id)
        ).fetchall()
    assert actors == [{"actor": f"subject:{product['subject_id']}"}]


def test_http_authorization_filters_lists_and_rejects_other_application(product):
    client, admin_headers = product["client"], product["headers"]
    app_id, case_id, _ = setup_case(product)
    auditor, _ = product["issue"]("auditor", app_id)
    assert client.get(f"/api/investigations/{case_id}/context", headers=auditor).status_code == 200
    assert (
        client.post(
            f"/api/applications/{app_id}/inventory/refresh", headers=auditor, json={}
        ).status_code
        == 403
    )
    other_app = client.post(
        "/api/applications",
        headers=admin_headers,
        json={"name": "Other", "repository": "test/other"},
    ).json()["id"]
    assert (
        client.get(f"/api/applications/{other_app}/inventory", headers=auditor).status_code == 404
    )
    assert [row["id"] for row in client.get("/api/applications", headers=auditor).json()] == [
        app_id
    ]
    assert client.get("/api/integrations", headers=auditor).status_code == 403


def test_deployment_import_is_scoped_and_append_only(product):
    client, headers = product["client"], product["headers"]
    app_id, _, _ = setup_case(product)
    inventory = client.post(
        f"/api/applications/{app_id}/inventory/refresh", headers=headers, json={}
    ).json()
    record = {
        "application_id": app_id,
        "snapshot_id": inventory["id"],
        "environment": "production",
        "artifact_ref": "test@sha256:fixture",
        "source_reference": "synthetic:test",
        "deployed_at": datetime.now(UTC).isoformat(),
    }
    body = {"schema_version": 1, "deployments": [record]}
    assert (
        client.post(
            f"/api/applications/{app_id}/deployments", headers=headers, json=body
        ).status_code
        == 201
    )
    record["application_id"] = str(uuid4())
    assert (
        client.post(
            f"/api/applications/{app_id}/deployments", headers=headers, json=body
        ).status_code
        == 422
    )
    data = client.get(f"/api/applications/{app_id}/inventory", headers=headers).json()
    assert len(data["deployments"]) == 1


def test_zetaris_reads_are_required_and_cannot_substitute_the_pinned_inventory(product):
    client, headers = product["client"], product["headers"]
    app_id, _, _ = setup_case(product)
    snapshot = client.post(
        f"/api/applications/{app_id}/inventory/refresh", headers=headers, json={}
    ).json()
    with product["connect"](product["settings"]) as connection:
        serialized = connection.execute(
            "SELECT payload FROM warden_inventory_data WHERE id=%s", (snapshot["id"],)
        ).fetchone()["payload"]

        class Reader:
            def query(self, statement, timeout):
                assert str(snapshot["id"]) in statement and str(app_id) in statement
                assert statement.endswith("LIMIT 1")
                return SimpleNamespace(
                    columns=["payload"], rows=[[serialized]], sources=["registered.inventory"]
                )

        settings = product["settings"].model_copy(
            update={
                "warden_data_mode": "zetaris",
                "warden_zetaris_inventory_table": "registered.inventory",
            }
        )
        gateway = CaseData(settings, time.monotonic() + 5, client=Reader())
        row, components = gateway.snapshot(connection, snapshot["id"], app_id)
        assert row["commit_ref"] == SHA and components
        changed = json.loads(serialized)
        changed["components"][0]["resolved_version"] = "99.0.0"
        serialized = json.dumps(changed)
        with pytest.raises(ValueError, match="pinned snapshot"):
            gateway.snapshot(connection, snapshot["id"], app_id)
        with pytest.raises(ProviderError, match="Configure"):
            CaseData(
                settings.model_copy(update={"warden_zetaris_inventory_table": ""}),
                time.monotonic() + 5,
                client=Reader(),
            ).snapshot(connection, snapshot["id"], app_id)


def test_identity_management_and_revocation_use_real_credentials(product):
    client, headers = product["client"], product["headers"]
    schema = client.get("/openapi.json").json()
    assert "IndividualCredential" in schema["components"]["securitySchemes"]
    subject = client.post(
        "/api/identity/subjects",
        headers=headers,
        json={
            "display_name": "Auditor fixture",
            "assignments": [{"role": "auditor", "application_id": None}],
        },
    )
    assert subject.status_code == 201, subject.text
    subject_id = subject.json()["subject_id"]
    issued = client.post(
        f"/api/identity/subjects/{subject_id}/credentials",
        headers=headers,
        json={"label": "fixture"},
    )
    assert issued.status_code == 201, issued.text
    body = issued.json()
    actor = {"Authorization": f"Bearer {body['token']}"}
    assert client.get("/api/identity/session", headers=actor).status_code == 200
    assert (
        client.post(
            "/api/applications", headers=actor, json={"name": "Denied", "repository": "test/repo"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/identity/credentials/{body['credential_id']}/revocation", headers=headers
        ).status_code
        == 200
    )
    assert client.get("/api/identity/session", headers=actor).status_code == 401
    assert "no-store" in issued.headers["cache-control"]


def test_model_dispatch_is_denied_without_an_explicit_policy(product):
    app_id, case_id, _ = setup_case(product)
    response = product["client"].post(
        f"/api/investigations/{case_id}/synthesis", headers=product["headers"]
    )
    assert response.status_code == 403


def test_provider_checks_do_not_invent_access_without_configuration(product):
    for adapter in ("meterless", "zetaris"):
        response = product["client"].post(
            f"/api/integrations/{adapter}/check", headers=product["headers"]
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "unconfigured"
        assert response.json()["verified"] is False


def test_hmem_conformance_check_and_feedback_do_not_change_exposure(product):
    client, headers = product["client"], product["headers"]
    check = client.post("/api/integrations/hmem/check", headers=headers)
    assert check.status_code == 200, check.text
    assert check.json()["verified"] is True
    assert check.json()["operation"] == "conformance"
    app_id, case_id, _ = setup_case(product)
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
        assert (
            client.post(
                f"/api/investigations/{case_id}/runs/{run['id']}/advance", headers=headers
            ).status_code
            == 200
        )
    before = client.get(f"/api/investigations/{case_id}", headers=headers).json()["exposure"]
    context = client.get(f"/api/investigations/{case_id}/context", headers=headers).json()
    memory_id = context["memory"]["memories"][0]["id"]
    feedback = client.post(
        f"/api/investigations/{case_id}/memory/feedback",
        headers=headers,
        json={"memory_id": memory_id, "kind": "helpful"},
    )
    assert feedback.status_code == 200, feedback.text
    assert feedback.json()["delta"] == 0.05
    queried = client.post(
        f"/api/investigations/{case_id}/memory/query",
        headers=headers,
        json={"query": "lodash advisory", "threshold": 0},
    )
    assert queried.status_code == 200, queried.text
    assert queried.json()["engine"] == "hmem"
    preview = client.post(f"/api/investigations/{case_id}/memory/sleep", headers=headers, json={})
    assert preview.status_code == 200, preview.text
    assert preview.json()["report"] is None
    after = client.get(f"/api/investigations/{case_id}", headers=headers).json()["exposure"]
    assert after == before


def test_authorized_model_bridge_sends_only_minimized_fields_and_does_not_set_exposure(
    product, monkeypatch
):
    client, headers = product["client"], product["headers"]
    app_id, case_id, _ = setup_case(product)
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
    observed = []

    class FixtureModel:
        def __init__(self, **_kwargs):
            pass

        def generate_investigation(self, **kwargs):
            observed.append(kwargs)
            return ModelResult(
                provider="meterless",
                model="meterless/auto",
                text="Synthetic proposal",
                structured_output={"proposals": [{"statement": "Review the lockfile"}]},
            )

    monkeypatch.setattr("alaira_warden.integration.routes.MeterlessClient", FixtureModel)
    client.app.state.settings = product["settings"].model_copy(
        update={
            "warden_model_dispatch_policy": "allow_minimized",
            "warden_meterless_base_url": "http://127.0.0.1:8088/v1",
            "warden_meterless_model": "meterless/auto",
        }
    )
    before = client.get(f"/api/investigations/{case_id}", headers=headers).json()["exposure"]
    result = client.post(f"/api/investigations/{case_id}/synthesis", headers=headers)
    assert result.status_code == 201, result.text
    assert len(observed) == 1
    assert "lodash" in observed[0]["task"]
    assert "Synthetic dataset" not in observed[0]["task"]
    assert observed[0]["max_output_tokens"] == 512
    assert result.json()["evidence"] is False
    assert result.json()["engine_verified"] is True
    assert (
        client.get(f"/api/investigations/{case_id}", headers=headers).json()["exposure"] == before
    )


def test_inventory_stage_fails_closed_when_zetaris_views_are_missing(product):
    app_id, case_id, _ = setup_case(product)
    snapshot = (
        product["client"]
        .post(
            f"/api/applications/{app_id}/inventory/refresh",
            headers=product["headers"],
            json={},
        )
        .json()
    )
    settings = product["settings"].model_copy(
        update={"warden_data_mode": "zetaris", "warden_zetaris_inventory_table": ""}
    )
    output = ProductServices(settings, transport=PublicFixtures()).inventory_stage(
        StageContext(
            uuid4(),
            UUID(str(app_id)),
            UUID(str(case_id)),
            "tester",
            "inventory:v1",
            time.monotonic() + 30,
            lambda: False,
            {},
            UUID(str(snapshot["id"])),
            GHSA,
            "zetaris",
        )
    )
    assert output.status == "blocked"
    assert output.reason == "unsupported"


def test_planner_evaluator_is_fail_open_and_never_changes_exposure(product):
    calls = []

    class Critic:
        def generate_text(self, **kwargs):
            calls.append(kwargs)
            return ModelResult(
                provider="meterless", model="meterless/auto", text="Do not change exposure."
            )

    configured = product["settings"].model_copy(
        update={
            "warden_model_dispatch_policy": "allow_minimized",
            "warden_meterless_base_url": "http://127.0.0.1:8088/v1",
            "warden_meterless_api_key": "nightshift-token",
            "warden_meterless_model": "meterless/auto",
        }
    )
    ready = run_planner_evaluator(configured, assessment_ids=["a"], client=Critic())
    assert ready["status"] == "ready"
    assert ready["changed_exposure"] is False
    assert len(calls) == 2
    skipped = run_planner_evaluator(product["settings"], assessment_ids=["a"], client=Critic())
    assert skipped["status"] == "skipped"
    assert skipped["changed_exposure"] is False
