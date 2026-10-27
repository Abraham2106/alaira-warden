"""The shared development token never becomes an implicit administrator."""

from uuid import uuid4

import pytest
from pydantic import SecretStr, ValidationError

from alaira_warden.identity.credentials import credential_digest, generate_token
from alaira_warden.identity.errors import AuthenticationRequired, IdentityConfigurationError
from alaira_warden.identity.principal import DEVELOPMENT_SUBJECT_ID, Assignment, authorize
from alaira_warden.identity.services import (
    Authenticator,
    IdentitySettings,
    development_principal,
    provision_initial_administrator,
)
from alaira_warden.identity.store import MemoryIdentityStore
from tests.identity.conftest import PEPPER, PEPPER_TEXT


class CountingStore(MemoryIdentityStore):
    def __init__(self) -> None:
        super().__init__()
        self.lookups = 0

    def resolve_credential(self, token: str, pepper: bytes):
        self.lookups += 1
        return super().resolve_credential(token, pepper)


def test_development_mode_rejects_global_and_non_development_environments():
    shared = generate_token()
    with pytest.raises(ValidationError):
        IdentitySettings(
            mode="development_shared",
            environment="production",
            credential_pepper=SecretStr(PEPPER_TEXT),
            shared_development_token=SecretStr(shared),
        )
    with pytest.raises(ValidationError):
        IdentitySettings(
            mode="development_shared",
            environment="test",
            credential_pepper=SecretStr(PEPPER_TEXT),
            shared_development_token=SecretStr("short-token"),
        )
    with pytest.raises(ValidationError):
        IdentitySettings(
            mode="development_shared",
            environment="test",
            credential_pepper=SecretStr(PEPPER_TEXT),
            shared_development_token=SecretStr(shared),
            development_assignments=(Assignment(role="administrador", application_id=uuid4()),),
        )
    with pytest.raises(ValidationError):
        IdentitySettings(
            mode="development_shared",
            environment="test",
            credential_pepper=SecretStr(PEPPER_TEXT),
            shared_development_token=SecretStr(shared),
            development_assignments=(Assignment(role="auditor", application_id=None),),
        )


def test_individual_mode_rejects_the_shared_token_before_the_store():
    store = CountingStore()
    issued = provision_initial_administrator(store, display_name="Ada Admin", pepper=PEPPER)
    shared = generate_token()
    store.issue_credential_record(
        credential_id=uuid4(),
        subject_id=issued.subject_id,
        token_hash=credential_digest(shared, PEPPER),
        label="planted-admin",
    )
    settings = IdentitySettings(
        mode="individual",
        environment="test",
        credential_pepper=SecretStr(PEPPER_TEXT),
        shared_development_token=SecretStr(shared),
        development_assignments=(Assignment(role="desarrollador", application_id=uuid4()),),
    )
    authenticator = Authenticator(store, settings)
    with pytest.raises(AuthenticationRequired):
        authenticator.authenticate(shared)
    assert store.lookups == 0
    planted = store.resolve_credential(shared, PEPPER)
    assert planted is not None
    assert planted.principal.roles == ("administrador",)
    assert store.lookups == 1
    store.lookups = 0
    admin = authenticator.authenticate(issued.reveal_token())
    assert admin.subject_id == issued.subject_id
    assert admin.roles == ("administrador",)
    with pytest.raises(IdentityConfigurationError):
        development_principal(settings)


def test_development_token_does_not_inherit_a_stored_administrator():
    store = CountingStore()
    issued = provision_initial_administrator(store, display_name="Ada Admin", pepper=PEPPER)
    shared = generate_token()
    store.issue_credential_record(
        credential_id=uuid4(),
        subject_id=issued.subject_id,
        token_hash=credential_digest(shared, PEPPER),
        label="planted-admin",
    )
    app_id = uuid4()
    settings = IdentitySettings(
        mode="development_shared",
        environment="development",
        credential_pepper=SecretStr(PEPPER_TEXT),
        shared_development_token=SecretStr(shared),
        development_assignments=(Assignment(role="desarrollador", application_id=app_id),),
    )
    authenticator = Authenticator(store, settings)
    principal = authenticator.authenticate(shared)
    assert store.lookups == 0
    assert principal.subject_id == DEVELOPMENT_SUBJECT_ID
    assert principal.subject_id != issued.subject_id
    assert principal.authentication_method == "development_shared_token"
    assert "administrador" not in principal.roles
    assert authorize(principal, "patch.prepare", app_id).allowed is True
    assert authorize(principal, "approval.decide", app_id).allowed is False
    assert authorize(principal, "patch.prepare", uuid4()).reason == "missing_assignment"
    assert authorize(principal, "settings.manage", None).allowed is False
    real_admin = authenticator.authenticate(issued.reveal_token())
    assert real_admin.subject_id == issued.subject_id
    assert store.lookups == 1


def test_unscoped_development_token_authenticates_without_authority():
    shared = generate_token()
    settings = IdentitySettings(
        mode="development_shared",
        environment="test",
        credential_pepper=SecretStr(PEPPER_TEXT),
        shared_development_token=SecretStr(shared),
    )
    principal = Authenticator(MemoryIdentityStore(), settings).authenticate(shared)
    assert principal.roles == ()
    assert principal.platform_roles == ()
    assert authorize(principal, "application.read", uuid4()).allowed is False
    assert authorize(principal, "application.create", None).allowed is False
    assert authorize(principal, "settings.manage", None).allowed is False
    assert authorize(principal, "change.merge", None).allowed is False
