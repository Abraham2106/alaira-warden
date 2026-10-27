from pathlib import Path

import pytest

from alaira_warden.db import SchemaNotReady, migration_manifest, verify_schema


class MigrationRows:
    def __init__(self, rows):
        self.rows = rows

    def execute(self, _query):
        return self

    def fetchall(self):
        return [{"name": name, "checksum": checksum} for name, checksum in self.rows.items()]


def test_readiness_rejects_missing_modified_or_unexpected_migrations(tmp_path: Path):
    (tmp_path / "001_test.sql").write_text("SELECT 1;", encoding="utf-8")
    expected = migration_manifest(tmp_path)
    verify_schema(MigrationRows(expected), tmp_path)
    for actual in ({}, {"001_test.sql": "wrong"}, {**expected, "002_future.sql": "unknown"}):
        with pytest.raises(SchemaNotReady):
            verify_schema(MigrationRows(actual), tmp_path)


def test_readiness_rejects_missing_migration_files(tmp_path: Path):
    with pytest.raises(SchemaNotReady):
        migration_manifest(tmp_path)
