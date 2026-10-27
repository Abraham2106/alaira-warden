import json
from datetime import UTC, datetime

import pytest

from alaira_warden.intelligence.dependabot import fetch_dependabot_alert
from alaira_warden.intelligence.errors import SourceError
from alaira_warden.intelligence.github import normalize_github_advisory
from alaira_warden.intelligence.grouping import group_advisories
from alaira_warden.intelligence.http import HttpResponse
from tests.test_product_integration import GHSA, setup_case


def alert(state="open"):
    vulnerability = {
        "package": {"ecosystem": "npm", "name": "lodash"},
        "vulnerable_version_range": "<4.17.21",
    }
    return {
        "number": 7,
        "state": state,
        "dependency": {"manifest_path": "package-lock.json", "scope": "runtime"},
        "security_advisory": {
            "ghsa_id": GHSA,
            "summary": "Controlled alert",
            "vulnerabilities": [vulnerability],
        },
        "security_vulnerability": vulnerability,
    }


class Transport:
    def __init__(self, status=200, state="open"):
        self.status, self.state, self.requests = status, state, []

    def send(self, request):
        self.requests.append(request)
        return HttpResponse(self.status, {}, json.dumps(alert(self.state)).encode())


def test_alert_preserves_provenance_and_shared_lineage():
    transport = Transport(state="fixed")
    record = fetch_dependabot_alert("owner/repo", 7, token="test", transport=transport)
    public, _ = normalize_github_advisory(
        alert()["security_advisory"], retrieved_at=datetime.now(UTC)
    )
    assert len(group_advisories([record, public]).groups) == 1
    assert record.origin["provider"] == "dependabot"
    assert record.origin["state"] == "fixed"
    assert record.affected_complete is False
    assert record.known_exploited is None
    assert record.source_status != "withdrawn"
    assert transport.requests[0].method == "GET"
    assert transport.requests[0].url.endswith("/repos/owner/repo/dependabot/alerts/7")


@pytest.mark.parametrize(
    "status,category",
    [(401, "unauthorized"), (403, "forbidden"), (404, "invalid_response"), (429, "rate_limited")],
)
def test_alert_failure_is_not_empty_safety_result(status, category):
    with pytest.raises(SourceError) as failure:
        fetch_dependabot_alert("owner/repo", 7, token="test", transport=Transport(status))
    assert failure.value.category == category


def test_invalid_repository_and_missing_token_never_send():
    transport = Transport()
    for repository in ("../repo", "owner/repo/other", "https://evil/repo"):
        with pytest.raises(ValueError):
            fetch_dependabot_alert(repository, 7, token="test", transport=transport)
    with pytest.raises(SourceError, match="token_required"):
        fetch_dependabot_alert("owner/repo", 7, token="", transport=transport)
    assert not transport.requests


def test_import_is_scoped_idempotent_and_keeps_revisions(product):
    app_id, _, _ = setup_case(product)
    from alaira_warden.integration.routes import get_services
    from alaira_warden.integration.services import ProductServices

    transport = Transport()
    services = ProductServices(
        product["settings"].model_copy(update={"warden_github_token": "test"}), transport=transport
    )
    # model_copy skips validation; use the same secret type as Settings.
    from pydantic import SecretStr

    services.settings.warden_github_token = SecretStr("test")
    client, headers = product["client"], product["headers"]
    client.app.dependency_overrides[get_services] = lambda: services
    url = f"/api/applications/{app_id}/dependabot/import"
    outsider, _ = product["issue"]("auditor", None)
    assert client.post(url, headers=outsider, json={"alert_number": 7}).status_code == 403
    assert not transport.requests
    first = client.post(url, headers=headers, json={"alert_number": 7})
    assert first.status_code == 200, first.text
    first = first.json()
    second = client.post(url, headers=headers, json={"alert_number": 7}).json()
    assert first["created"] is True and second["created"] is False
    assert first["investigation"]["id"] == second["investigation"]["id"]
    case_id = first["investigation"]["id"]
    context = client.get(f"/api/investigations/{case_id}/context", headers=headers).json()
    assert len(context["evidence"]) == 1
    transport.state = "dismissed"
    assert client.post(url, headers=headers, json={"alert_number": 7}).status_code == 200
    context = client.get(f"/api/investigations/{case_id}/context", headers=headers).json()
    assert len(context["evidence"]) == 2
    assert (
        client.get(f"/api/investigations/{case_id}", headers=headers).json()["status"] == "detected"
    )
