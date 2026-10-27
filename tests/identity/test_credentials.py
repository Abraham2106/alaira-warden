import inspect
from uuid import uuid4

import pytest
from pydantic import SecretStr, ValidationError

from alaira_warden.identity.credentials import credential_digest, generate_token, is_well_formed
from alaira_warden.identity.errors import (
    AuthenticationRequired,
    IdentityRejected,
    PermissionDenied,
    ProvisioningClosed,
)
from alaira_warden.identity.principal import audit_actor, authorize
from alaira_warden.identity.services import (
    IdentitySettings,
    issue_subject_credential,
    provision_initial_administrator,
    set_subject_active,
)
from alaira_warden.identity.store import PostgresIdentityStore
from tests.identity.conftest import PEPPER, principal_with


def test_issued_credential_is_not_stored_or_serialized(store, settings):
    issued = provision_initial_administrator(store, display_name="Ada Admin", pepper=PEPPER)
    token = issued.reveal_token()
    assert is_well_formed(token)
    assert token not in store.stored_secrets()
    digest = credential_digest(token, PEPPER)
    assert digest in store.stored_secrets()
    assert token not in digest
    dumped = issued.model_dump()
    assert dumped["token"] == "**********"
    assert token not in repr(issued)
    assert "wdn_" not in repr(issued)
    resolved = store.resolve_credential(token, PEPPER)
    assert resolved is not None
    assert resolved.principal.roles == ("administrador",)
    assert resolved.principal.platform_roles == ("administrador",)
    assert resolved.principal.authentication_method == "api_credential"
    assert audit_actor(resolved.principal) == f"subject:{resolved.principal.subject_id}"
    assert token not in audit_actor(resolved.principal)
    assert digest not in audit_actor(resolved.principal)
    assert settings.pepper_bytes() == PEPPER
    second = issue_subject_credential(
        store, resolved.principal, resolved.principal.subject_id, pepper=PEPPER, label="laptop"
    )
    listed = str(
        [item.public_dict() for item in store.list_credentials(resolved.principal.subject_id)]
    )
    assert second.reveal_token() not in listed
    assert token not in listed
    assert "token_hash" not in listed
    set_subject_active(store, resolved.principal, resolved.principal.subject_id, is_active=False)
    inactive = store.resolve_credential(token, PEPPER)
    assert inactive is not None
    assert authorize(inactive.principal, "settings.manage", None).reason == "inactive"


def test_unknown_revoked_and_inactive_credentials_do_not_authorize(store):
    issued = provision_initial_administrator(store, display_name="Ada Admin", pepper=PEPPER)
    token = issued.reveal_token()
    assert store.resolve_credential(generate_token(), PEPPER) is None
    assert store.resolve_credential(token, b"different-pepper-value") is None
    with pytest.raises(AuthenticationRequired):
        store.resolve_credential("not-a-credential", PEPPER)
    revoked = store.revoke_credential(issued.credential_id)
    assert revoked is not None
    assert revoked.revoked_at is not None
    assert "token_hash" not in revoked.public_dict()
    assert token not in str(revoked.public_dict())
    assert store.resolve_credential(token, PEPPER) is None
    again = provision_initial_administrator
    with pytest.raises(ProvisioningClosed):
        again(store, display_name="Second Admin", pepper=PEPPER)
    assert token not in store.stored_secrets()


def test_initial_provision_has_no_public_back_door(store):
    with pytest.raises(IdentityRejected):
        provision_initial_administrator(store, display_name=" ", pepper=PEPPER)
    with pytest.raises(IdentityRejected):
        provision_initial_administrator(store, display_name="wdn_not-a-name", pepper=PEPPER)
    assert store.has_subjects() is False
    developer = principal_with("desarrollador", uuid4())
    with pytest.raises(PermissionDenied):
        issue_subject_credential(store, developer, uuid4(), pepper=PEPPER, label="laptop")
    assert store.credentials == []
    source = inspect.getsource(provision_initial_administrator)
    assert "admin123" not in source
    assert "password" not in source.lower()


def test_short_pepper_and_second_bootstrap_fail_closed(store):
    with pytest.raises(ValidationError):
        IdentitySettings(credential_pepper=SecretStr("short"), environment="test")
    issued = provision_initial_administrator(store, display_name="Ada Admin", pepper=PEPPER)
    with pytest.raises(ProvisioningClosed):
        provision_initial_administrator(store, display_name="Ada Admin", pepper=PEPPER)
    assert store.resolve_credential(issued.reveal_token(), PEPPER) is not None


def test_postgres_repository_does_not_apply_ddl_on_import():
    source = inspect.getsource(PostgresIdentityStore)
    assert "CREATE TABLE" not in source.upper()
    assert ".format(" not in source
    assert "psycopg.connect" not in source
