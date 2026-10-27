"""Provisioning and authentication. Neither path trusts a client-supplied role."""

import hmac
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_serializer, model_validator

from alaira_warden.identity.credentials import (
    credential_digest,
    generate_token,
    is_well_formed,
    require_pepper,
)
from alaira_warden.identity.errors import (
    AuthenticationRequired,
    IdentityConfigurationError,
    IdentityReferenceError,
    IdentityRejected,
    IdentityUnavailable,
    PermissionDenied,
    ProvisioningClosed,
)
from alaira_warden.identity.principal import (
    DEVELOPMENT_SUBJECT_ID,
    SETTINGS_MANAGE,
    Assignment,
    Principal,
    authorize,
    build_principal,
)
from alaira_warden.identity.store import (
    CredentialMetadata,
    IdentityStore,
    SubjectView,
)


class IssuedCredential(BaseModel):
    """`token` stays masked if the model is dumped. Call `reveal_token` once, at issuance."""

    model_config = ConfigDict(extra="forbid")

    credential_id: UUID
    subject_id: UUID
    token: SecretStr

    def reveal_token(self) -> str:
        return self.token.get_secret_value()

    @field_serializer("token")
    def mask_token(self, _value: SecretStr) -> str:
        return "**********"


class IdentitySettings(BaseModel):
    """Individual mode is the default. Development mode cannot grant platform admin."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: str = "individual"
    environment: str = "development"
    credential_pepper: SecretStr
    shared_development_token: SecretStr = SecretStr("")
    development_assignments: tuple[Assignment, ...] = ()

    @model_validator(mode="after")
    def fail_closed(self) -> "IdentitySettings":
        if self.mode not in {"individual", "development_shared"}:
            raise ValueError("Identity mode is not recognized.")
        pepper = self.credential_pepper.get_secret_value().encode("utf-8")
        if len(pepper) < 16:
            raise ValueError("Credential pepper must be at least 16 bytes.")
        if self.mode != "development_shared":
            return self
        token = self.shared_development_token.get_secret_value()
        if len(token) < 16:
            raise ValueError("Development token must be an explicit secret.")
        if self.environment not in {"development", "test"}:
            raise ValueError("Development shared token is unavailable in this environment.")
        for assignment in self.development_assignments:
            if assignment.role == "administrador" or assignment.application_id is None:
                raise ValueError("Development mode cannot grant administrador or platform scope.")
        return self

    def pepper_bytes(self) -> bytes:
        return require_pepper(self.credential_pepper.get_secret_value().encode("utf-8"))


def _matches(presented: str, expected: str) -> bool:
    if not expected:
        return False
    try:
        return hmac.compare_digest(presented.encode(), expected.encode())
    except Exception:
        return False


def _clean_text(value: str, *, limit: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > limit or "wdn_" in cleaned.lower():
        raise IdentityRejected("The request was rejected.")
    return cleaned


def development_principal(settings: IdentitySettings) -> Principal:
    if settings.mode != "development_shared":
        raise IdentityConfigurationError("Identity configuration is incomplete.")
    return build_principal(
        DEVELOPMENT_SUBJECT_ID,
        is_active=True,
        assignments=settings.development_assignments,
        authentication_method="development_shared_token",
    )


class Authenticator:
    def __init__(self, store: IdentityStore, settings: IdentitySettings) -> None:
        self.store = store
        self.settings = settings

    def authenticate(self, bearer: str | None) -> Principal:
        if bearer is None or not bearer.strip():
            raise AuthenticationRequired("Authentication required.")
        shared = self.settings.shared_development_token.get_secret_value()
        if self.settings.mode == "individual":
            if _matches(bearer, shared):
                raise AuthenticationRequired("Authentication required.")
            return self._individual(bearer)
        if self.settings.mode == "development_shared":
            if self.settings.environment not in {"development", "test"}:
                raise IdentityConfigurationError("Identity configuration is incomplete.")
            if _matches(bearer, shared):
                return development_principal(self.settings)
            return self._individual(bearer)
        raise IdentityConfigurationError("Identity configuration is incomplete.")

    def _individual(self, bearer: str) -> Principal:
        if not is_well_formed(bearer):
            raise AuthenticationRequired("Authentication required.")
        pepper = self.settings.pepper_bytes()
        try:
            resolved = self.store.resolve_credential(bearer, pepper)
        except (AuthenticationRequired, IdentityConfigurationError):
            raise
        except Exception:
            raise IdentityUnavailable("Identity store unavailable.") from None
        if resolved is None:
            raise AuthenticationRequired("Authentication required.")
        return resolved.principal


def _require_admin(principal: Principal | None) -> None:
    if authorize(principal, SETTINGS_MANAGE, None).allowed is not True:
        raise PermissionDenied("Forbidden.")


def provision_initial_administrator(
    store: IdentityStore,
    *,
    display_name: str,
    pepper: bytes,
    label: str = "initial-administrator",
) -> IssuedCredential:
    """One empty-store bootstrap. Not an HTTP route and not a known credential."""
    require_pepper(pepper)
    cleaned_name = _clean_text(display_name, limit=200)
    cleaned_label = _clean_text(label, limit=120)
    if store.has_subjects():
        raise ProvisioningClosed("Initial administrator provisioning is closed.")
    token = generate_token()
    subject_id = uuid4()
    credential_id = uuid4()
    store.provision_initial(
        subject_id=subject_id,
        display_name=cleaned_name,
        credential_id=credential_id,
        token_hash=credential_digest(token, pepper),
        label=cleaned_label,
    )
    return IssuedCredential(
        credential_id=credential_id,
        subject_id=subject_id,
        token=SecretStr(token),
    )


def create_subject(
    store: IdentityStore,
    principal: Principal | None,
    *,
    display_name: str,
    assignments: list[Assignment] | tuple[Assignment, ...] = (),
) -> SubjectView:
    _require_admin(principal)
    subject_id = uuid4()
    rows = [(uuid4(), item.role, item.application_id) for item in assignments]
    store.create_subject_with_assignments(
        subject_id=subject_id,
        display_name=_clean_text(display_name, limit=200),
        assignments=rows,
    )
    for view in store.list_subjects():
        if view.subject_id == subject_id:
            return view
    raise IdentityUnavailable("Identity store unavailable.")


def issue_subject_credential(
    store: IdentityStore,
    principal: Principal | None,
    subject_id: UUID,
    *,
    pepper: bytes,
    label: str,
) -> IssuedCredential:
    _require_admin(principal)
    require_pepper(pepper)
    if not store.subject_exists(subject_id):
        raise IdentityReferenceError("Related record was not found.")
    token = generate_token()
    credential_id = uuid4()
    store.issue_credential_record(
        credential_id=credential_id,
        subject_id=subject_id,
        token_hash=credential_digest(token, require_pepper(pepper)),
        label=_clean_text(label, limit=120),
    )
    return IssuedCredential(
        credential_id=credential_id,
        subject_id=subject_id,
        token=SecretStr(token),
    )


def revoke_subject_credential(
    store: IdentityStore,
    principal: Principal | None,
    credential_id: UUID,
) -> CredentialMetadata:
    _require_admin(principal)
    found = store.revoke_credential(credential_id)
    if found is None:
        raise IdentityReferenceError("Related record was not found.")
    return found


def set_subject_active(
    store: IdentityStore,
    principal: Principal | None,
    subject_id: UUID,
    *,
    is_active: bool,
) -> None:
    _require_admin(principal)
    if not store.set_active(subject_id, is_active):
        raise IdentityReferenceError("Related record was not found.")


def list_identity_subjects(store: IdentityStore, principal: Principal | None) -> list[SubjectView]:
    _require_admin(principal)
    return store.list_subjects()


def list_subject_credentials(
    store: IdentityStore,
    principal: Principal | None,
    subject_id: UUID,
) -> list[CredentialMetadata]:
    _require_admin(principal)
    return store.list_credentials(subject_id)


class SubjectDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=1, max_length=200)
    assignments: list[Assignment] = Field(default_factory=list)
