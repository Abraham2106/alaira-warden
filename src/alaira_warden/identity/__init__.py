"""Individual credentials and deny-by-default authorization for ALAIRA Warden."""

from alaira_warden.identity.dispatch import authorize_model_dispatch, model_dispatch_allowed
from alaira_warden.identity.http import (
    IdentityAuth,
    application_scope_id,
    create_identity_router,
    enforce_application,
    enforce_platform,
)
from alaira_warden.identity.principal import (
    AUDIT_READ,
    DEVELOPMENT_SUBJECT_ID,
    PROHIBITED_ACTIONS,
    Principal,
    application_scope,
    audit_actor,
    audit_event,
    authorize,
    fail_closed,
    operation_actor,
    select_visible,
)
from alaira_warden.identity.services import (
    IdentitySettings,
    development_principal,
    provision_initial_administrator,
)
from alaira_warden.identity.sql import PROPOSED_IDENTITY_DDL
from alaira_warden.identity.store import MemoryIdentityStore, PostgresIdentityStore

__all__ = [
    "AUDIT_READ",
    "DEVELOPMENT_SUBJECT_ID",
    "PROHIBITED_ACTIONS",
    "PROPOSED_IDENTITY_DDL",
    "IdentityAuth",
    "IdentitySettings",
    "MemoryIdentityStore",
    "PostgresIdentityStore",
    "Principal",
    "application_scope",
    "application_scope_id",
    "audit_actor",
    "audit_event",
    "authorize",
    "authorize_model_dispatch",
    "create_identity_router",
    "development_principal",
    "enforce_application",
    "enforce_platform",
    "fail_closed",
    "model_dispatch_allowed",
    "operation_actor",
    "provision_initial_administrator",
    "select_visible",
]
