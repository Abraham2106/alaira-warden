import hashlib
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from alaira_warden.config import Settings, get_settings


class SchemaNotReady(RuntimeError):
    """The database does not match this application's migration files."""


def migration_manifest(directory: Path = Path("migrations")) -> dict[str, str]:
    files = sorted(directory.glob("[0-9]*.sql"))
    if not files:
        raise SchemaNotReady("Migration files unavailable.")
    return {
        file.name: hashlib.sha256(file.read_text(encoding="utf-8").encode()).hexdigest()
        for file in files
    }


def verify_schema(connection, directory: Path = Path("migrations")) -> None:
    expected = migration_manifest(directory)
    applied = {
        row["name"]: row["checksum"]
        for row in connection.execute("SELECT name, checksum FROM schema_migrations").fetchall()
    }
    if applied != expected:
        raise SchemaNotReady("Pending, changed or unexpected database migrations.")


@contextmanager
def connect(settings: Settings):
    # One connection per operation is sufficient for this scaffold; pooling comes with load.
    with psycopg.connect(
        settings.warden_database_url.get_secret_value(),
        row_factory=dict_row,
        connect_timeout=3,
        options="-c statement_timeout=5000",
    ) as connection:
        yield connection


def migrate(directory: Path = Path("migrations"), settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if settings.warden_migration_database_url.get_secret_value():
        settings = settings.model_copy(
            update={"warden_database_url": settings.warden_migration_database_url}
        )
    files = sorted(directory.glob("[0-9]*.sql"))
    if not files:
        raise RuntimeError("No migration files found. Run from the repository root.")
    with connect(settings) as connection:
        # Serialize migrations from simultaneous startup jobs in one transaction.
        connection.execute("SELECT pg_advisory_xact_lock(817402)")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(name TEXT PRIMARY KEY, checksum TEXT NOT NULL, "
            "applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        for file in files:
            content = file.read_text(encoding="utf-8")
            checksum = hashlib.sha256(content.encode()).hexdigest()
            previous = connection.execute(
                "SELECT checksum FROM schema_migrations WHERE name = %s", (file.name,)
            ).fetchone()
            if previous:
                if previous["checksum"] != checksum:
                    raise RuntimeError(f"Previously applied migration changed: {file.name}")
                continue
            connection.execute(content)
            connection.execute(
                "INSERT INTO schema_migrations (name, checksum) VALUES (%s, %s)",
                (file.name, checksum),
            )
            print(f"Applied {file.name}")


if __name__ == "__main__":
    migrate()
    # Both operations are explicit owner-side migrations, never API startup DDL.
    from alaira_warden.orchestration.checkpoints import setup_checkpoints

    setup_checkpoints(get_settings())
