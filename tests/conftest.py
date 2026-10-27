import os
from contextlib import contextmanager
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import conninfo_to_dict

from alaira_warden.config import Settings
from alaira_warden.db import connect, migrate
from alaira_warden.identity import PostgresIdentityStore
from alaira_warden.identity.credentials import credential_digest, generate_token
from alaira_warden.main import create_app
from alaira_warden.orchestration.checkpoints import checkpoint_connection, setup_checkpoints


@pytest.fixture
def product(monkeypatch):
    url = os.getenv("WARDEN_TEST_DATABASE_URL")
    if not url:
        pytest.skip("No isolated PostgreSQL configured")
    assert conninfo_to_dict(url).get("dbname", "").endswith("_test")
    settings = Settings(
        _env_file=None,
        warden_database_url=url,
        warden_identity_pepper="integration-test-pepper-32-bytes",
    )
    with connect(settings) as connection:
        if not connection.execute("SELECT 1 FROM pg_roles WHERE rolname='warden_app'").fetchone():
            connection.execute("CREATE ROLE warden_app NOLOGIN")
    migrate(settings=settings)
    setup_checkpoints(settings)

    @contextmanager
    def runtime(configuration):
        with connect(configuration) as connection:
            connection.execute("SET LOCAL ROLE warden_app")
            yield connection

    @contextmanager
    def checkpoints(configuration):
        with checkpoint_connection(configuration) as connection:
            connection.execute("SET ROLE warden_app")
            yield connection

    for module in (
        "repository",
        "integration.auth",
        "integration.routes",
        "integration.services",
        "orchestration.runtime",
        "agents.traces",
        "agents.response",
    ):
        monkeypatch.setattr(f"alaira_warden.{module}.connect", runtime)
    monkeypatch.setattr("alaira_warden.orchestration.runtime.checkpoint_connection", checkpoints)

    def issue(role="administrador", application_id=None):
        subject_id, token = uuid4(), generate_token()
        with runtime(settings) as connection:
            store = PostgresIdentityStore(connection)
            store.create_subject_with_assignments(
                subject_id=subject_id,
                display_name="Synthetic",
                assignments=[(uuid4(), role, application_id)],
            )
            store.issue_credential_record(
                credential_id=uuid4(),
                subject_id=subject_id,
                token_hash=credential_digest(
                    token, settings.warden_identity_pepper.get_secret_value().encode()
                ),
                label="integration-test",
            )
        return {"Authorization": f"Bearer {token}"}, subject_id

    headers, subject_id = issue()
    with TestClient(create_app(settings)) as client:
        yield {
            "settings": settings,
            "client": client,
            "headers": headers,
            "subject_id": subject_id,
            "issue": issue,
            "connect": runtime,
        }
