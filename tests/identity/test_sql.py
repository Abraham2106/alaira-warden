import os

import pytest
from psycopg.conninfo import conninfo_to_dict

from alaira_warden.identity.sql import PROPOSED_IDENTITY_DDL, PROVISION_ADVISORY_LOCK


def test_proposed_ddl_stores_digests_and_does_not_connect():
    ddl = PROPOSED_IDENTITY_DDL
    assert "token_hash" in ddl
    assert "revoked_at" in ddl
    assert "GRANT UPDATE (revoked_at)" in ddl
    assert "password" not in ddl.lower()
    assert "token TEXT" not in ddl
    assert "CREATE TABLE identity_credentials" in ddl
    assert PROVISION_ADVISORY_LOCK != 817402


def assert_isolated_test_database(url: str) -> str:
    name = conninfo_to_dict(url).get("dbname", "")
    if not name.endswith("_test"):
        raise RuntimeError("Refusing a database whose name does not end with _test.")
    return name


def test_sql_guard_refuses_the_demo_database_name_without_connecting():
    with pytest.raises(RuntimeError):
        assert_isolated_test_database("postgresql://warden_app:local@localhost:5432/warden")
    assert assert_isolated_test_database("postgresql://localhost/warden_identity_test") == (
        "warden_identity_test"
    )


@pytest.mark.skipif(
    not os.getenv("WARDEN_IDENTITY_TEST_DATABASE_URL"),
    reason="No isolated identity test database configured",
)
def test_postgres_store_roundtrip_on_isolated_database():
    import psycopg
    from psycopg.rows import dict_row

    from alaira_warden.identity.services import provision_initial_administrator
    from alaira_warden.identity.store import PostgresIdentityStore

    url = os.environ["WARDEN_IDENTITY_TEST_DATABASE_URL"]
    assert_isolated_test_database(url)
    with psycopg.connect(url, row_factory=dict_row, connect_timeout=3) as connection:
        connection.execute(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'warden_app') "
            "THEN CREATE ROLE warden_app NOLOGIN; END IF; END $$"
        )
        connection.execute("DROP SCHEMA IF EXISTS identity_front_trial CASCADE")
        connection.execute("CREATE SCHEMA identity_front_trial")
        connection.execute("SET search_path TO identity_front_trial")
        try:
            connection.execute(
                "CREATE TABLE applications (id UUID PRIMARY KEY, name TEXT NOT NULL)"
            )
            for statement in PROPOSED_IDENTITY_DDL.split(";"):
                sql = statement.strip()
                if sql:
                    connection.execute(sql)
            store = PostgresIdentityStore(connection)
            issued = provision_initial_administrator(
                store, display_name="Ada Admin", pepper=b"identity-test-pepper"
            )
            resolved = store.resolve_credential(issued.reveal_token(), b"identity-test-pepper")
            assert resolved is not None
            assert resolved.principal.platform_roles == ("administrador",)
            listed = [row.public_dict() for row in store.list_credentials(issued.subject_id)]
            assert issued.reveal_token() not in str(listed)
            store.revoke_credential(issued.credential_id)
            assert store.resolve_credential(issued.reveal_token(), b"identity-test-pepper") is None
        finally:
            connection.execute("DROP SCHEMA IF EXISTS identity_front_trial CASCADE")
