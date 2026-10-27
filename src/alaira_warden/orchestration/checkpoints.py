"""Owner-only setup, runtime-only checkpoint access. Never call setup from a request."""

from contextlib import contextmanager

import psycopg
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from psycopg.rows import dict_row

from alaira_warden.config import Settings, get_settings


@contextmanager
def checkpoint_connection(settings: Settings, *, owner: bool = False):
    secret = settings.warden_database_url
    if owner and settings.warden_migration_database_url.get_secret_value():
        secret = settings.warden_migration_database_url
    # Autocommit is required by official migrations (CREATE INDEX CONCURRENTLY).
    with psycopg.connect(
        secret.get_secret_value(),
        autocommit=True,
        row_factory=dict_row,
        connect_timeout=3,
        options="-c search_path=warden_workflow -c statement_timeout=5000",
    ) as connection:
        yield connection


def saver(connection) -> PostgresSaver:
    return PostgresSaver(
        connection,
        serde=JsonPlusSerializer(
            pickle_fallback=False, allowed_json_modules=(), allowed_msgpack_modules=()
        ),
    )


def setup_checkpoints(settings: Settings) -> None:
    """Explicit migration command. Use the schema owner, never runtime credentials."""
    with checkpoint_connection(settings, owner=True) as connection:
        connection.execute("SELECT pg_advisory_lock(817403)")
        try:
            connection.execute("CREATE SCHEMA IF NOT EXISTS warden_workflow")
            saver(connection).setup()
            # A dedicated schema prevents the checkpoint dependency from owning domain tables.
            connection.execute("REVOKE ALL ON SCHEMA warden_workflow FROM PUBLIC")
            if connection.execute("SELECT 1 FROM pg_roles WHERE rolname = 'warden_app'").fetchone():
                connection.execute("GRANT USAGE ON SCHEMA warden_workflow TO warden_app")
                connection.execute(
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES "
                    "IN SCHEMA warden_workflow TO warden_app"
                )
                connection.execute(
                    "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON "
                    "warden_workflow.checkpoint_migrations FROM warden_app"
                )
        finally:
            connection.execute("SELECT pg_advisory_unlock(817403)")


def verify_checkpoints(connection) -> None:
    versions = connection.execute("SELECT v FROM checkpoint_migrations ORDER BY v").fetchall()
    if [row["v"] for row in versions] != list(range(len(PostgresSaver.MIGRATIONS))):
        raise RuntimeError("Checkpoint schema is not ready for this dependency version.")


if __name__ == "__main__":
    setup_checkpoints(get_settings())
