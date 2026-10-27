from uuid import UUID, uuid4

from alaira_warden.config import Settings
from alaira_warden.db import connect, verify_schema
from alaira_warden.models import ApplicationCreate, InvestigationCreate


class Repository:
    def __init__(self, settings: Settings):
        self.settings = settings

    def ready(self) -> None:
        with connect(self.settings) as connection:
            verify_schema(connection)
            connection.execute("SELECT id FROM applications LIMIT 0")
            connection.execute("SELECT id FROM investigations LIMIT 0")
            connection.execute("SELECT id FROM audit_events LIMIT 0")

    def applications(self) -> list[dict]:
        with connect(self.settings) as connection:
            return connection.execute(
                "SELECT * FROM applications ORDER BY created_at DESC, id DESC LIMIT 100"
            ).fetchall()

    def create_application(self, application: ApplicationCreate) -> dict:
        with connect(self.settings) as connection:
            row = connection.execute(
                "INSERT INTO applications (id, name, repository) VALUES (%s, %s, %s) RETURNING *",
                (uuid4(), application.name, application.repository),
            ).fetchone()
            connection.execute(
                "INSERT INTO audit_events (entity_id, actor, action) VALUES (%s, %s, %s)",
                (row["id"], "local-developer", "application.created"),
            )
            return row

    def investigations(self) -> list[dict]:
        with connect(self.settings) as connection:
            return connection.execute(
                "SELECT * FROM investigations ORDER BY created_at DESC, id DESC LIMIT 100"
            ).fetchall()

    def investigation(self, identifier: UUID) -> dict | None:
        with connect(self.settings) as connection:
            return connection.execute(
                "SELECT * FROM investigations WHERE id = %s", (identifier,)
            ).fetchone()

    def create_investigation(self, investigation: InvestigationCreate) -> dict:
        with connect(self.settings) as connection:
            row = connection.execute(
                "INSERT INTO investigations (id, application_id, title, source_url, description) "
                "VALUES (%s, %s, %s, %s, %s) RETURNING *",
                (
                    uuid4(),
                    investigation.application_id,
                    investigation.title,
                    str(investigation.source_url),
                    investigation.description,
                ),
            ).fetchone()
            connection.execute(
                "INSERT INTO audit_events (entity_id, actor, action) VALUES (%s, %s, %s)",
                (row["id"], "local-developer", "investigation.created"),
            )
            return row
