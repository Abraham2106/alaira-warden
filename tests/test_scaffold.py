import json

import psycopg
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from alaira_warden.adapters import AdapterNotImplemented, invoke
from alaira_warden.config import Settings
from alaira_warden.db import SchemaNotReady
from alaira_warden.main import create_app, get_repository
from alaira_warden.models import ApplicationCreate
from alaira_warden.workflow import build_workflow


@pytest.fixture
def client():
    settings = Settings(_env_file=None, warden_api_token="test-token")
    with TestClient(create_app(settings)) as connection:
        yield connection


def test_liveness_does_not_require_database(client):
    assert client.get("/health/live").json()["status"] == "ok"


@pytest.mark.parametrize("path", ["/api/applications", "/api/investigations", "/api/integrations"])
def test_api_rejects_missing_token(client, path):
    assert client.get(path).status_code == 401


def test_wrong_token_cannot_create_application(client):
    response = client.post(
        "/api/applications",
        headers={"Authorization": "Bearer wrong"},
        json={"name": "Test", "repository": "owner/repository"},
    )
    assert response.status_code == 401


def test_unconfigured_auth_fails_closed():
    with TestClient(create_app(Settings(_env_file=None, warden_api_token=""))) as client:
        response = client.get("/api/integrations")
        assert response.status_code == 503


def test_pending_integrations_are_not_reported_as_verified(client):
    response = client.get("/api/integrations", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    rows = response.json()
    assert {row["id"] for row in rows} >= {"meterless", "osv", "nvd", "cisa-kev", "syft", "trivy"}
    assert all(row["status"] == "not_implemented" and row["verified"] is False for row in rows)


def test_configured_secret_is_not_verified_or_echoed():
    secret = "super-secret-github-token"
    settings = Settings(
        _env_file=None,
        warden_api_token="test-token",
        warden_github_token=secret,
    )
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/integrations", headers={"Authorization": "Bearer test-token"})
    rows = response.json()
    github = next(row for row in rows if row["id"] == "github")
    assert github["auth"]["configured"] is True
    assert github["verified"] is False
    assert github["status"] == "not_implemented"
    payload = json.dumps(rows)
    assert secret not in payload
    assert "ghp_" not in payload
    with pytest.raises(AdapterNotImplemented, match="not implemented"):
        invoke(settings, "github")


def test_readiness_reports_database_failure_without_leaking_error(client):
    class OfflineRepository:
        def ready(self):
            raise psycopg.OperationalError("sensitive connection details")

    client.app.dependency_overrides[get_repository] = OfflineRepository
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert "sensitive" not in response.text


def test_readiness_rejects_an_outdated_schema(client):
    class OutdatedRepository:
        def ready(self):
            raise SchemaNotReady("Internal migration details")

    client.app.dependency_overrides[get_repository] = OutdatedRepository
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert "Internal migration" not in response.text


@pytest.mark.parametrize("repository", ["../../etc/passwd", "https://github.com/a/b", "a/.."])
def test_repositories_cannot_be_local_paths_or_urls(repository):
    with pytest.raises(ValidationError):
        ApplicationCreate(name="Test", repository=repository)


def test_index_and_assets_are_served(client):
    index = client.get("/")
    assert index.status_code == 200
    assert "ALAIRA Warden" in index.text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/app.css").status_code == 200


def test_preview_stops_without_claiming_a_scan_or_patch():
    result = build_workflow().invoke(
        {
            "case_id": "case-test",
            "mode": "scaffold_preview",
            "status": "detected",
            "stages": [],
            "blockers": [],
        }
    )
    assert result["status"] == "requires_intervention"
    assert result["blockers"]
    assert result["stages"] == ["intake", "inventory_gate"]
    assert "patch" not in result and "exposure" not in result
