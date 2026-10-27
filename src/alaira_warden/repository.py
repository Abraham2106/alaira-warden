from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from alaira_warden.config import Settings
from alaira_warden.db import connect, verify_schema
from alaira_warden.identity import application_scope
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
            connection.execute("SELECT id FROM identity_subjects LIMIT 0")
            connection.execute("SELECT id FROM assessments LIMIT 0")
            connection.execute("SELECT id FROM warden_inventory_data LIMIT 0")
            connection.execute("SELECT id FROM agent_events LIMIT 0")

    def integration_checks(self):
        with connect(self.settings) as connection:
            return connection.execute(
                "SELECT DISTINCT ON (adapter) adapter,payload "
                "FROM integration_checks ORDER BY adapter,checked_at DESC,id DESC"
            ).fetchall()

    def application(self, identifier: UUID) -> dict | None:
        with connect(self.settings) as connection:
            return connection.execute(
                "SELECT * FROM applications WHERE id=%s", (identifier,)
            ).fetchone()

    def applications(self, principal) -> list[dict]:
        scope = application_scope(principal, "application.read")
        with connect(self.settings) as connection:
            return connection.execute(
                "SELECT * FROM applications WHERE %s OR id=ANY(%s::uuid[]) "
                "ORDER BY created_at DESC, id DESC LIMIT 100",
                (scope.unrestricted, list(scope.application_ids)),
            ).fetchall()

    def create_application(self, application: ApplicationCreate, *, actor: str) -> dict:
        with connect(self.settings) as connection:
            row = connection.execute(
                "INSERT INTO applications (id, name, repository, owner, organization, criticality, "
                "environments) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                (
                    uuid4(),
                    application.name,
                    application.repository,
                    application.owner,
                    application.organization,
                    application.criticality,
                    Jsonb(application.environments),
                ),
            ).fetchone()
            connection.execute(
                "INSERT INTO audit_events (entity_id, actor, action) VALUES (%s, %s, %s)",
                (row["id"], actor, "application.created"),
            )
            return row

    def investigations(self, principal) -> list[dict]:
        scope = application_scope(principal, "investigation.read")
        with connect(self.settings) as connection:
            return connection.execute(
                "SELECT * FROM investigations WHERE %s OR application_id=ANY(%s::uuid[]) "
                "ORDER BY created_at DESC, id DESC LIMIT 100",
                (scope.unrestricted, list(scope.application_ids)),
            ).fetchall()

    def investigation(self, identifier: UUID) -> dict | None:
        with connect(self.settings) as connection:
            return connection.execute(
                "SELECT * FROM investigations WHERE id = %s", (identifier,)
            ).fetchone()

    def create_investigation(self, investigation: InvestigationCreate, *, actor: str) -> dict:
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
                (row["id"], actor, "investigation.created"),
            )
            return row
