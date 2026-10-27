"""Optional real database smoke test. CI provides an isolated PostgreSQL service."""

import os
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import conninfo_to_dict
from psycopg.errors import InsufficientPrivilege

from alaira_warden.config import Settings
from alaira_warden.db import connect, migrate
from alaira_warden.main import create_app
from alaira_warden.repository import Repository


@pytest.mark.skipif(
    not os.getenv("WARDEN_TEST_DATABASE_URL"), reason="No isolated PostgreSQL test URL configured"
)
def test_migrations_and_persistent_api_roundtrip(monkeypatch):
    url = os.environ["WARDEN_TEST_DATABASE_URL"]
    assert conninfo_to_dict(url).get("dbname", "").endswith("_test"), (
        "Only a database with a name ending in _test may run this check."
    )
    settings = Settings(_env_file=None, warden_database_url=url, warden_api_token="postgres-test")
    with connect(settings) as connection:
        if not connection.execute("SELECT 1 FROM pg_roles WHERE rolname = 'warden_app'").fetchone():
            connection.execute("CREATE ROLE warden_app NOLOGIN")
    directory = Path(__file__).resolve().parents[1] / "migrations"
    migrate(directory, settings)
    migrate(directory, settings)

    @contextmanager
    def runtime_connection(runtime_settings):
        with connect(runtime_settings) as connection:
            connection.execute("SET LOCAL ROLE warden_app")
            yield connection

    # Exercise the actual application privileges, not the schema owner's privileges.
    monkeypatch.setattr("alaira_warden.repository.connect", runtime_connection)
    Repository(settings).ready()
    headers = {"Authorization": "Bearer postgres-test"}
    with TestClient(create_app(settings)) as client:
        assert client.get("/health/ready").status_code == 200
        application = client.post(
            "/api/applications",
            headers=headers,
            json={"name": "Prueba persistente", "repository": "test-owner/test-repository"},
        )
        assert application.status_code == 201
        app_id = application.json()["id"]
        investigation = client.post(
            "/api/investigations",
            headers=headers,
            json={
                "application_id": app_id,
                "title": "Aviso de prueba",
                "source_url": "https://example.com/advisory",
                "description": "Datos sintéticos; no se ejecuta ningún escaneo.",
            },
        )
        assert investigation.status_code == 201
        case_id = investigation.json()["id"]
        detail = client.get(f"/api/investigations/{case_id}", headers=headers)
        assert detail.json()["exposure"] == "undetermined"
        preview = client.post(f"/api/investigations/{case_id}/preview", headers=headers)
        assert preview.json()["status"] == "requires_intervention"
        assert client.get(f"/api/investigations/{case_id}", headers=headers).json()["status"] == (
            "detected"
        )
    with connect(settings) as connection:
        permissions = connection.execute(
            "SELECT has_table_privilege('warden_app', 'audit_events', 'INSERT') AS can_insert, "
            "has_table_privilege('warden_app', 'audit_events', 'UPDATE') AS can_update, "
            "has_table_privilege('warden_app', 'schema_migrations', 'INSERT') AS can_migrate"
        ).fetchone()
        assert permissions == {"can_insert": True, "can_update": False, "can_migrate": False}
        events = connection.execute(
            "SELECT action FROM audit_events WHERE entity_id IN (%s, %s)", (app_id, case_id)
        ).fetchall()
        assert {event["action"] for event in events} == {
            "application.created",
            "investigation.created",
        }
        connection.execute("SET LOCAL ROLE warden_app")
        with pytest.raises(InsufficientPrivilege):
            connection.execute(
                "UPDATE audit_events SET actor = 'tampered' WHERE entity_id = %s", (app_id,)
            )
