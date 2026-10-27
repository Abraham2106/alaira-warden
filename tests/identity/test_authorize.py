"""Negative authorization tests. Expected grants are specified here, not read from RULES."""

from uuid import uuid4

import pytest

from alaira_warden.identity.principal import (
    Principal,
    application_scope,
    audit_actor,
    audit_event,
    authorize,
    fail_closed,
    operation_actor,
    select_visible,
)
from tests.identity.conftest import principal_with

APP_A = uuid4()
APP_B = uuid4()

APPLICATION_GRANTS = {
    "application.read": {"administrador", "analista", "desarrollador", "aprobador", "auditor"},
    "inventory.read": {"administrador", "analista", "desarrollador", "aprobador", "auditor"},
    "inventory.refresh": {"administrador", "desarrollador"},
    "investigation.read": {"administrador", "analista", "desarrollador", "aprobador", "auditor"},
    "investigation.create": {"administrador", "analista"},
    "investigation.review": {"administrador", "analista"},
    "patch.prepare": {"administrador", "desarrollador"},
    "approval.decide": {"administrador", "aprobador"},
    "pull_request.publish": {"administrador", "aprobador"},
    "audit.read": {"administrador", "auditor"},
}
PLATFORM_GRANTS = {
    "application.create": {"administrador"},
    "settings.manage": {"administrador"},
    "audit.read": {"administrador", "auditor"},
}
PROHIBITED = ("change.merge", "change.deploy", "infrastructure.change", "secret.manipulate")
ROLES = ("administrador", "analista", "desarrollador", "aprobador", "auditor")


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("action", tuple(APPLICATION_GRANTS))
def test_application_role_matrix(role, action):
    decision = authorize(principal_with(role, APP_A), action, APP_A)
    assert decision.allowed is (role in APPLICATION_GRANTS[action])
    if decision.allowed:
        assert decision.reason == "allowed"
    else:
        assert decision.reason == "role_denied"


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("action", tuple(APPLICATION_GRANTS))
def test_assignment_to_a_does_not_cover_b(role, action):
    decision = authorize(principal_with(role, APP_A), action, APP_B)
    assert decision.allowed is False
    assert decision.reason == "missing_assignment"


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("action", tuple(PLATFORM_GRANTS))
def test_platform_actions_require_a_platform_assignment(role, action):
    decision = authorize(principal_with(role, APP_A), action, None)
    assert decision.allowed is False
    assert decision.reason == "missing_assignment"


@pytest.mark.parametrize("action", tuple(APPLICATION_GRANTS))
def test_platform_administrator_is_explicit_and_not_implied_by_a_single_app(action):
    platform = principal_with("administrador", None)
    scoped = principal_with("administrador", APP_A)
    assert platform.application_ids == ()
    assert authorize(platform, action, APP_B).allowed is True
    assert authorize(scoped, action, APP_B).allowed is False
    assert authorize(scoped, "settings.manage", None).allowed is False
    assert authorize(platform, "settings.manage", None).allowed is True


def test_platform_auditor_reads_audit_and_cannot_mutate():
    principal = principal_with("auditor", None)
    assert authorize(principal, "audit.read", None).allowed is True
    assert authorize(principal, "audit.read", APP_A).allowed is True
    assert authorize(principal, "application.read", APP_B).allowed is True
    for action in ("application.create", "patch.prepare", "approval.decide", "settings.manage"):
        assert (
            authorize(
                principal,
                action,
                None if action.endswith("create") or action.startswith("settings") else APP_A,
            ).allowed
            is False
        )


def test_scoped_auditor_cannot_create_patch_or_approve():
    principal = principal_with("auditor", APP_A)
    assert authorize(principal, "application.create", None).allowed is False
    assert authorize(principal, "patch.prepare", APP_A).allowed is False
    assert authorize(principal, "approval.decide", APP_A).allowed is False
    assert authorize(principal, "investigation.create", APP_A).allowed is False
    assert authorize(principal, "audit.read", APP_A).allowed is True
    assert authorize(principal, "audit.read", None).allowed is False


def test_developer_without_approver_cannot_decide_or_publish():
    principal = principal_with("desarrollador", APP_A)
    assert authorize(principal, "patch.prepare", APP_A).allowed is True
    assert authorize(principal, "approval.decide", APP_A).reason == "role_denied"
    assert authorize(principal, "pull_request.publish", APP_A).allowed is False
    other = authorize(principal, "approval.decide", APP_B)
    assert other.allowed is False
    assert other.reason == "missing_assignment"


def test_inactive_identity_and_missing_assignment_deny():
    inactive = principal_with("administrador", None, active=False)
    assert authorize(inactive, "settings.manage", None).reason == "inactive"
    assert authorize(inactive, "application.read", APP_A).allowed is False
    bare = Principal(
        subject_id=uuid4(),
        is_active=True,
        authentication_method="api_credential",
        roles=("administrador",),
        application_ids=(APP_A,),
        platform_roles=("administrador",),
    )
    assert bare.roles == ()
    assert bare.platform_roles == ()
    assert authorize(bare, "settings.manage", None).reason == "missing_assignment"
    assert authorize(bare, "application.read", APP_A).reason == "missing_assignment"


def test_client_role_list_does_not_override_assignments():
    principal = Principal.model_validate(
        {
            "subject_id": str(uuid4()),
            "roles": ["administrador"],
            "platform_roles": ["administrador"],
            "application_ids": [str(APP_B)],
            "is_active": True,
            "authentication_method": "api_credential",
            "assignments": [{"role": "auditor", "application_id": str(APP_A)}],
        }
    )
    assert principal.roles == ("auditor",)
    assert authorize(principal, "settings.manage", None).allowed is False
    assert authorize(principal, "patch.prepare", APP_A).allowed is False
    assert authorize(principal, "audit.read", APP_A).allowed is True
    assert authorize(principal, "audit.read", APP_B).reason == "missing_assignment"


@pytest.mark.parametrize("action", PROHIBITED)
@pytest.mark.parametrize("role", ROLES)
def test_mvp_blocks_merge_deploy_infrastructure_and_secrets(role, action):
    assert authorize(principal_with(role, APP_A), action, APP_A).reason == "prohibited"
    assert authorize(principal_with("administrador", None), action, None).allowed is False


def test_unknown_action_and_wrong_scope_deny():
    admin = principal_with("administrador", None)
    assert authorize(admin, "application.delete", APP_A).reason == "unknown_action"
    assert authorize(admin, "application.read", None).reason == "scope_required"
    assert authorize(admin, "settings.manage", APP_A).reason == "platform_only"
    assert (
        authorize({"roles": ["administrador"]}, "settings.manage", None).reason == "unauthenticated"
    )
    assert fail_closed(None, "settings.manage") is False
    assert fail_closed(object(), "application.read", APP_A) is False
    assert fail_closed(admin, "settings.manage", None) is True


def test_empty_scope_does_not_mean_every_application():
    rows = [{"id": APP_A, "name": "a"}, {"id": APP_B, "name": "b"}, {"name": "orphan"}]
    developer = principal_with("desarrollador", APP_A)
    assert select_visible(rows, developer, "application.read", key="id") == [rows[0]]
    assert select_visible(rows, None, "application.read", key="id") == []
    assert select_visible(rows, principal_with("auditor", APP_A), "patch.prepare", key="id") == []
    platform = principal_with("administrador", None)
    assert application_scope(platform, "application.read").unrestricted is True
    assert select_visible(rows, platform, "application.read", key="id") == rows
    assert application_scope(developer, "settings.manage").unrestricted is False
    assert application_scope(developer, "settings.manage").application_ids == ()


def test_audit_actor_follows_the_principal_and_drops_secrets():
    principal = principal_with("desarrollador", APP_A)
    forged = operation_actor(principal, client_actor="local-developer")
    assert forged == f"subject:{principal.subject_id}"
    assert forged == audit_actor(principal)
    assert "local-developer" not in forged
    event = audit_event(
        principal,
        entity_id=APP_A,
        action="application.created",
        detail={
            "authorization": "Bearer wdn_should-not-persist",
            "token_hash": "abc123",
            "note": "prefix wdn_plaintext stays out",
            "repository": "owner/name",
        },
    )
    rendered = str(event)
    assert "wdn_" not in rendered
    assert "abc123" not in rendered
    assert event["actor"] == forged
    assert event["detail"]["repository"] == "owner/name"
