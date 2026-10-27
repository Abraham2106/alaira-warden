from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr

from alaira_warden.identity.principal import Assignment, Principal
from alaira_warden.identity.services import IdentitySettings
from alaira_warden.identity.store import MemoryIdentityStore

PEPPER = b"identity-test-pepper"
PEPPER_TEXT = "identity-test-pepper"


@pytest.fixture
def pepper() -> bytes:
    return PEPPER


@pytest.fixture
def store() -> MemoryIdentityStore:
    return MemoryIdentityStore()


@pytest.fixture
def settings() -> IdentitySettings:
    return IdentitySettings(credential_pepper=SecretStr(PEPPER_TEXT), environment="test")


def principal_with(
    role: str,
    application_id: UUID | None,
    *,
    active: bool = True,
    subject_id: UUID | None = None,
) -> Principal:
    return Principal(
        subject_id=subject_id or uuid4(),
        is_active=active,
        authentication_method="api_credential",
        assignments=(Assignment(role=role, application_id=application_id),),
    )
