"""Identity persistence. SQL is parameterized and is not executed on import."""

from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from alaira_warden.identity.credentials import credential_digest, digests_match
from alaira_warden.identity.errors import (
    IdentityConflict,
    IdentityError,
    IdentityReferenceError,
    IdentityRejected,
    IdentityStoreError,
    ProvisioningClosed,
)
from alaira_warden.identity.principal import (
    ROLES,
    Assignment,
    Principal,
    build_principal,
)
from alaira_warden.identity.sql import PROVISION_ADVISORY_LOCK


class ResolvedCredential:
    __slots__ = ("credential_id", "principal")

    def __init__(self, credential_id: UUID, principal: Principal) -> None:
        self.credential_id = credential_id
        self.principal = principal


class CredentialMetadata:
    __slots__ = ("credential_id", "created_at", "label", "revoked_at", "subject_id")

    def __init__(
        self,
        credential_id: UUID,
        subject_id: UUID,
        label: str,
        created_at: datetime,
        revoked_at: datetime | None,
    ) -> None:
        self.credential_id = credential_id
        self.subject_id = subject_id
        self.label = label
        self.created_at = created_at
        self.revoked_at = revoked_at

    def public_dict(self) -> dict[str, object]:
        return {
            "credential_id": str(self.credential_id),
            "subject_id": str(self.subject_id),
            "label": self.label,
            "created_at": self.created_at.isoformat(),
            "revoked_at": None if self.revoked_at is None else self.revoked_at.isoformat(),
        }


class SubjectView:
    __slots__ = ("assignments", "display_name", "is_active", "subject_id")

    def __init__(
        self,
        subject_id: UUID,
        display_name: str,
        is_active: bool,
        assignments: tuple[Assignment, ...],
    ) -> None:
        self.subject_id = subject_id
        self.display_name = display_name
        self.is_active = is_active
        self.assignments = assignments

    def public_dict(self) -> dict[str, object]:
        return {
            "subject_id": str(self.subject_id),
            "display_name": self.display_name,
            "is_active": self.is_active,
            "assignments": [
                {
                    "role": item.role,
                    "application_id": None
                    if item.application_id is None
                    else str(item.application_id),
                }
                for item in self.assignments
            ],
        }


class IdentityStore(Protocol):
    def has_subjects(self) -> bool: ...

    def resolve_credential(self, token: str, pepper: bytes) -> ResolvedCredential | None: ...

    def provision_initial(
        self,
        *,
        subject_id: UUID,
        display_name: str,
        credential_id: UUID,
        token_hash: str,
        label: str,
    ) -> None: ...

    def create_subject_with_assignments(
        self,
        *,
        subject_id: UUID,
        display_name: str,
        assignments: list[tuple[UUID, str, UUID | None]],
    ) -> None: ...

    def revoke_credential(self, credential_id: UUID) -> CredentialMetadata | None: ...

    def list_credentials(self, subject_id: UUID) -> list[CredentialMetadata]: ...

    def list_subjects(self) -> list[SubjectView]: ...

    def set_active(self, subject_id: UUID, is_active: bool) -> bool: ...

    def issue_credential_record(
        self,
        *,
        credential_id: UUID,
        subject_id: UUID,
        token_hash: str,
        label: str,
    ) -> None: ...

    def subject_exists(self, subject_id: UUID) -> bool: ...


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise IdentityRejected("The request was rejected.")


class MemoryIdentityStore:
    """Controlled store for tests. It keeps digests, never plaintext tokens."""

    def __init__(self) -> None:
        self.subjects: dict[UUID, dict[str, object]] = {}
        self.assignments: list[dict[str, object]] = []
        self.credentials: list[dict[str, object]] = []

    def has_subjects(self) -> bool:
        return bool(self.subjects)

    def subject_exists(self, subject_id: UUID) -> bool:
        return subject_id in self.subjects

    def stored_secrets(self) -> str:
        return repr((self.subjects, self.assignments, self.credentials))

    def _assignments_for(self, subject_id: UUID) -> tuple[Assignment, ...]:
        return tuple(
            Assignment(role=row["role"], application_id=row["application_id"])  # type: ignore[arg-type]
            for row in self.assignments
            if row["subject_id"] == subject_id
        )

    def resolve_credential(self, token: str, pepper: bytes) -> ResolvedCredential | None:
        digest = credential_digest(token, pepper)
        for row in self.credentials:
            stored = str(row["token_hash"])
            if not digests_match(stored, digest):
                continue
            if row["revoked_at"] is not None:
                return None
            subject = self.subjects.get(row["subject_id"])  # type: ignore[arg-type]
            if subject is None:
                return None
            principal = build_principal(
                subject["id"],  # type: ignore[arg-type]
                is_active=bool(subject["is_active"]),
                assignments=self._assignments_for(subject["id"]),  # type: ignore[arg-type]
                authentication_method="api_credential",
            )
            return ResolvedCredential(row["id"], principal)  # type: ignore[arg-type]
        return None

    def provision_initial(
        self,
        *,
        subject_id: UUID,
        display_name: str,
        credential_id: UUID,
        token_hash: str,
        label: str,
    ) -> None:
        if self.subjects:
            raise ProvisioningClosed("Initial administrator provisioning is closed.")
        _check_role("administrador")
        self.subjects[subject_id] = {
            "id": subject_id,
            "display_name": display_name,
            "is_active": True,
        }
        self.assignments.append(
            {
                "id": uuid4(),
                "subject_id": subject_id,
                "role": "administrador",
                "application_id": None,
            }
        )
        now = datetime.now(UTC)
        self.credentials.append(
            {
                "id": credential_id,
                "subject_id": subject_id,
                "token_hash": token_hash,
                "label": label,
                "created_at": now,
                "revoked_at": None,
            }
        )

    def create_subject_with_assignments(
        self,
        *,
        subject_id: UUID,
        display_name: str,
        assignments: list[tuple[UUID, str, UUID | None]],
    ) -> None:
        if subject_id in self.subjects:
            raise IdentityConflict("The request conflicts with an existing record.")
        seen: set[tuple[str, str | None]] = set()
        for _assignment_id, role, application_id in assignments:
            _check_role(role)
            key = (role, None if application_id is None else str(application_id))
            if key in seen:
                raise IdentityConflict("The request conflicts with an existing record.")
            seen.add(key)
        self.subjects[subject_id] = {
            "id": subject_id,
            "display_name": display_name,
            "is_active": True,
        }
        for assignment_id, role, application_id in assignments:
            self.assignments.append(
                {
                    "id": assignment_id,
                    "subject_id": subject_id,
                    "role": role,
                    "application_id": application_id,
                }
            )

    def issue_credential_record(
        self,
        *,
        credential_id: UUID,
        subject_id: UUID,
        token_hash: str,
        label: str,
    ) -> None:
        if subject_id not in self.subjects:
            raise IdentityReferenceError("Related record was not found.")
        if any(row["token_hash"] == token_hash for row in self.credentials):
            raise IdentityConflict("The request conflicts with an existing record.")
        self.credentials.append(
            {
                "id": credential_id,
                "subject_id": subject_id,
                "token_hash": token_hash,
                "label": label,
                "created_at": datetime.now(UTC),
                "revoked_at": None,
            }
        )

    def revoke_credential(self, credential_id: UUID) -> CredentialMetadata | None:
        for row in self.credentials:
            if row["id"] != credential_id:
                continue
            if row["revoked_at"] is None:
                row["revoked_at"] = datetime.now(UTC)
            return _metadata(row)
        return None

    def list_credentials(self, subject_id: UUID) -> list[CredentialMetadata]:
        if subject_id not in self.subjects:
            raise IdentityReferenceError("Related record was not found.")
        rows = [row for row in self.credentials if row["subject_id"] == subject_id]
        return [_metadata(row) for row in rows]

    def list_subjects(self) -> list[SubjectView]:
        views: list[SubjectView] = []
        for subject in self.subjects.values():
            views.append(
                SubjectView(
                    subject["id"],  # type: ignore[arg-type]
                    str(subject["display_name"]),
                    bool(subject["is_active"]),
                    self._assignments_for(subject["id"]),  # type: ignore[arg-type]
                )
            )
        return views

    def set_active(self, subject_id: UUID, is_active: bool) -> bool:
        subject = self.subjects.get(subject_id)
        if subject is None:
            return False
        subject["is_active"] = is_active
        return True


def _metadata(row: dict[str, object]) -> CredentialMetadata:
    return CredentialMetadata(
        credential_id=row["id"],  # type: ignore[arg-type]
        subject_id=row["subject_id"],  # type: ignore[arg-type]
        label=str(row["label"]),
        created_at=row["created_at"],  # type: ignore[arg-type]
        revoked_at=row["revoked_at"],  # type: ignore[arg-type]
    )


def _convert_db_error(exc: Exception) -> Exception:
    if isinstance(exc, IdentityError):
        return exc
    import psycopg

    if isinstance(exc, psycopg.errors.UniqueViolation):
        return IdentityConflict("The request conflicts with an existing record.")
    if isinstance(exc, psycopg.errors.ForeignKeyViolation):
        return IdentityReferenceError("Related record was not found.")
    if isinstance(exc, psycopg.errors.CheckViolation | psycopg.errors.NotNullViolation):
        return IdentityRejected("The request was rejected.")
    if isinstance(exc, psycopg.Error):
        return IdentityStoreError("Identity store unavailable.")
    return exc


class PostgresIdentityStore:
    """Uses a caller-supplied connection. Does not open connections or apply DDL."""

    def __init__(self, connection: object) -> None:
        self.connection = connection

    def _execute(self, sql: str, params: tuple[object, ...]) -> list[dict]:
        try:
            cursor = self.connection.execute(sql, params)  # type: ignore[attr-defined]
            if cursor.description is None:
                return []
            rows = cursor.fetchall()
        except Exception as exc:
            raise _convert_db_error(exc) from None
        if any(not isinstance(row, dict) for row in rows):
            raise IdentityStoreError("Identity store unavailable.")
        return rows

    def has_subjects(self) -> bool:
        rows = self._execute("SELECT EXISTS (SELECT 1 FROM identity_subjects) AS present", ())
        return bool(rows and rows[0].get("present"))

    def subject_exists(self, subject_id: UUID) -> bool:
        rows = self._execute(
            "SELECT 1 AS found FROM identity_subjects WHERE id = %s",
            (subject_id,),
        )
        return bool(rows)

    def _assignment_models(self, subject_id: UUID) -> tuple[Assignment, ...]:
        rows = self._execute(
            "SELECT role, application_id FROM identity_assignments WHERE subject_id = %s "
            "ORDER BY role, application_id",
            (subject_id,),
        )
        return tuple(
            Assignment(role=row["role"], application_id=row["application_id"]) for row in rows
        )

    def resolve_credential(self, token: str, pepper: bytes) -> ResolvedCredential | None:
        digest = credential_digest(token, pepper)
        rows = self._execute(
            "SELECT c.id AS credential_id, c.token_hash, c.revoked_at, "
            "s.id AS subject_id, s.is_active "
            "FROM identity_credentials AS c "
            "JOIN identity_subjects AS s ON s.id = c.subject_id "
            "WHERE c.token_hash = %s",
            (digest,),
        )
        if not rows:
            return None
        row = rows[0]
        if not digests_match(str(row["token_hash"]), digest) or row["revoked_at"] is not None:
            return None
        principal = build_principal(
            row["subject_id"],
            is_active=bool(row["is_active"]),
            assignments=self._assignment_models(row["subject_id"]),
            authentication_method="api_credential",
        )
        return ResolvedCredential(row["credential_id"], principal)

    def provision_initial(
        self,
        *,
        subject_id: UUID,
        display_name: str,
        credential_id: UUID,
        token_hash: str,
        label: str,
    ) -> None:
        try:
            with self.connection.transaction():  # type: ignore[attr-defined]
                self._execute("SELECT pg_advisory_xact_lock(%s)", (PROVISION_ADVISORY_LOCK,))
                if self.has_subjects():
                    raise ProvisioningClosed("Initial administrator provisioning is closed.")
                self._execute(
                    "INSERT INTO identity_subjects (id, display_name) VALUES (%s, %s)",
                    (subject_id, display_name),
                )
                self._execute(
                    "INSERT INTO identity_assignments (id, subject_id, role, application_id) "
                    "VALUES (%s, %s, %s, %s)",
                    (uuid4(), subject_id, "administrador", None),
                )
                self._execute(
                    "INSERT INTO identity_credentials (id, subject_id, token_hash, label) "
                    "VALUES (%s, %s, %s, %s)",
                    (credential_id, subject_id, token_hash, label),
                )
        except Exception as exc:
            converted = _convert_db_error(exc)
            if converted is not exc:
                raise converted from None
            raise

    def create_subject_with_assignments(
        self,
        *,
        subject_id: UUID,
        display_name: str,
        assignments: list[tuple[UUID, str, UUID | None]],
    ) -> None:
        for _assignment_id, role, _application_id in assignments:
            _check_role(role)
        try:
            with self.connection.transaction():  # type: ignore[attr-defined]
                self._execute(
                    "INSERT INTO identity_subjects (id, display_name) VALUES (%s, %s)",
                    (subject_id, display_name),
                )
                for assignment_id, role, application_id in assignments:
                    self._execute(
                        "INSERT INTO identity_assignments "
                        "(id, subject_id, role, application_id) VALUES (%s, %s, %s, %s)",
                        (assignment_id, subject_id, role, application_id),
                    )
        except Exception as exc:
            converted = _convert_db_error(exc)
            if converted is not exc:
                raise converted from None
            raise

    def issue_credential_record(
        self,
        *,
        credential_id: UUID,
        subject_id: UUID,
        token_hash: str,
        label: str,
    ) -> None:
        self._execute(
            "INSERT INTO identity_credentials (id, subject_id, token_hash, label) "
            "VALUES (%s, %s, %s, %s)",
            (credential_id, subject_id, token_hash, label),
        )

    def revoke_credential(self, credential_id: UUID) -> CredentialMetadata | None:
        rows = self._execute(
            "UPDATE identity_credentials SET revoked_at = now() "
            "WHERE id = %s AND revoked_at IS NULL "
            "RETURNING id, subject_id, label, created_at, revoked_at",
            (credential_id,),
        )
        if rows:
            return _metadata(rows[0])
        existing = self._execute(
            "SELECT id, subject_id, label, created_at, revoked_at "
            "FROM identity_credentials WHERE id = %s",
            (credential_id,),
        )
        if not existing:
            return None
        return _metadata(existing[0])

    def list_credentials(self, subject_id: UUID) -> list[CredentialMetadata]:
        if not self.subject_exists(subject_id):
            raise IdentityReferenceError("Related record was not found.")
        rows = self._execute(
            "SELECT id, subject_id, label, created_at, revoked_at "
            "FROM identity_credentials WHERE subject_id = %s "
            "ORDER BY created_at DESC, id DESC",
            (subject_id,),
        )
        return [_metadata(row) for row in rows]

    def list_subjects(self) -> list[SubjectView]:
        rows = self._execute(
            "SELECT id, display_name, is_active FROM identity_subjects ORDER BY created_at, id",
            (),
        )
        return [
            SubjectView(
                row["id"],
                row["display_name"],
                bool(row["is_active"]),
                self._assignment_models(row["id"]),
            )
            for row in rows
        ]

    def set_active(self, subject_id: UUID, is_active: bool) -> bool:
        rows = self._execute(
            "UPDATE identity_subjects SET is_active = %s WHERE id = %s RETURNING id",
            (is_active, subject_id),
        )
        return bool(rows)
