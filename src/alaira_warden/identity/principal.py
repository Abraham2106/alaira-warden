"""Principals and deny-by-default authorization.

`roles`, `application_ids` and `platform_roles` are derived from `assignments`.
A client-supplied role list never grants access. Platform scope is an assignment
whose `application_id` is null, not a side effect of holding any credential.
"""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, model_validator

from alaira_warden.identity.errors import IdentityError

ADMINISTRADOR = "administrador"
ANALISTA = "analista"
DESARROLLADOR = "desarrollador"
APROBADOR = "aprobador"
AUDITOR = "auditor"

ROLES: frozenset[str] = frozenset({ADMINISTRADOR, ANALISTA, DESARROLLADOR, APROBADOR, AUDITOR})
READ_ROLES = ROLES

APPLICATION_READ = "application.read"
APPLICATION_CREATE = "application.create"
INVENTORY_READ = "inventory.read"
INVENTORY_REFRESH = "inventory.refresh"
INVESTIGATION_READ = "investigation.read"
INVESTIGATION_CREATE = "investigation.create"
INVESTIGATION_REVIEW = "investigation.review"
PATCH_PREPARE = "patch.prepare"
APPROVAL_DECIDE = "approval.decide"
PULL_REQUEST_PUBLISH = "pull_request.publish"
AUDIT_READ = "audit.read"
SETTINGS_MANAGE = "settings.manage"

# RF-37: the MVP rejects these even for a platform administrator.
MERGE_EXECUTE = "change.merge"
DEPLOY_EXECUTE = "change.deploy"
INFRASTRUCTURE_CHANGE = "infrastructure.change"
SECRET_MANIPULATE = "secret.manipulate"

PROHIBITED_ACTIONS: frozenset[str] = frozenset(
    {MERGE_EXECUTE, DEPLOY_EXECUTE, INFRASTRUCTURE_CHANGE, SECRET_MANIPULATE}
)

RoleName = Literal[
    "administrador",
    "analista",
    "desarrollador",
    "aprobador",
    "auditor",
]
AuthenticationMethod = Literal["api_credential", "development_shared_token"]
DecisionReason = Literal[
    "allowed",
    "unauthenticated",
    "inactive",
    "missing_assignment",
    "role_denied",
    "scope_required",
    "platform_only",
    "prohibited",
    "unknown_action",
]
ActionScope = Literal["application", "platform", "either"]

# Fixed local subject for the explicit development-token mode. Not an administrator.
DEVELOPMENT_SUBJECT_ID = UUID("00000000-0000-4000-8000-0000000000d1")


class Assignment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: RoleName
    application_id: UUID | None = None


class Principal(BaseModel):
    """Server-built identity. Assignments are the only authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_id: UUID
    roles: tuple[str, ...] = ()
    application_ids: tuple[UUID, ...] = ()
    is_active: bool
    authentication_method: AuthenticationMethod
    assignments: tuple[Assignment, ...] = ()
    platform_roles: tuple[str, ...] = ()

    @model_validator(mode="before")
    @classmethod
    def derive_views(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        raw = data.get("assignments") or ()
        normalized: list[dict[str, object]] = []
        roles: set[str] = set()
        platform: set[str] = set()
        applications: set[UUID] = set()
        for item in raw:
            if isinstance(item, Assignment):
                role = item.role
                application_id = item.application_id
            elif isinstance(item, dict):
                role = item.get("role")
                application_id = item.get("application_id")
            else:
                raise ValueError("Assignment is not valid.")
            if role not in ROLES:
                raise ValueError("Assignment is not valid.")
            normalized.append({"role": role, "application_id": application_id})
            roles.add(str(role))
            if application_id is None:
                platform.add(str(role))
            else:
                applications.add(
                    application_id
                    if isinstance(application_id, UUID)
                    else UUID(str(application_id))
                )
        derived = dict(data)
        derived["assignments"] = normalized
        derived["roles"] = tuple(sorted(roles))
        derived["platform_roles"] = tuple(sorted(platform))
        derived["application_ids"] = tuple(sorted(applications, key=str))
        return derived

    def public_dict(self) -> dict[str, object]:
        return {
            "subject_id": str(self.subject_id),
            "roles": list(self.roles),
            "application_ids": [str(item) for item in self.application_ids],
            "is_active": self.is_active,
            "authentication_method": self.authentication_method,
            "assignments": [
                {
                    "role": item.role,
                    "application_id": None
                    if item.application_id is None
                    else str(item.application_id),
                }
                for item in self.assignments
            ],
            "platform_roles": list(self.platform_roles),
        }


class ActionRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: ActionScope
    roles: frozenset[str]


def _rule(scope: ActionScope, roles: frozenset[str]) -> ActionRule:
    return ActionRule(scope=scope, roles=roles)


RULES: dict[str, ActionRule] = {
    APPLICATION_READ: _rule("application", READ_ROLES),
    INVENTORY_READ: _rule("application", READ_ROLES),
    INVESTIGATION_READ: _rule("application", READ_ROLES),
    INVENTORY_REFRESH: _rule("application", frozenset({ADMINISTRADOR, DESARROLLADOR})),
    INVESTIGATION_CREATE: _rule("application", frozenset({ADMINISTRADOR, ANALISTA})),
    INVESTIGATION_REVIEW: _rule("application", frozenset({ADMINISTRADOR, ANALISTA})),
    PATCH_PREPARE: _rule("application", frozenset({ADMINISTRADOR, DESARROLLADOR})),
    APPROVAL_DECIDE: _rule("application", frozenset({ADMINISTRADOR, APROBADOR})),
    PULL_REQUEST_PUBLISH: _rule("application", frozenset({ADMINISTRADOR, APROBADOR})),
    AUDIT_READ: _rule("either", frozenset({ADMINISTRADOR, AUDITOR})),
    APPLICATION_CREATE: _rule("platform", frozenset({ADMINISTRADOR})),
    SETTINGS_MANAGE: _rule("platform", frozenset({ADMINISTRADOR})),
}


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    action: str
    reason: DecisionReason
    application_id: UUID | None = None

    @model_validator(mode="after")
    def consistent(self) -> "Decision":
        if self.allowed != (self.reason == "allowed"):
            raise ValueError("Authorization decision is inconsistent.")
        return self


class ApplicationScope(BaseModel):
    """Visible applications for a list. `unrestricted` is true only for a platform role."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    unrestricted: bool = False
    application_ids: tuple[UUID, ...] = ()


def _deny(action: str, application_id: UUID | None, reason: DecisionReason) -> Decision:
    return Decision(allowed=False, action=action, reason=reason, application_id=application_id)


def _allow(action: str, application_id: UUID | None) -> Decision:
    return Decision(allowed=True, action=action, reason="allowed", application_id=application_id)


def _roles_for(principal: Principal, application_id: UUID | None) -> set[str]:
    matched: set[str] = set()
    for item in principal.assignments:
        if application_id is None:
            if item.application_id is None:
                matched.add(item.role)
        elif item.application_id is None or item.application_id == application_id:
            matched.add(item.role)
    return matched


def _covers(principal: Principal, application_id: UUID | None) -> bool:
    if application_id is None:
        return any(item.application_id is None for item in principal.assignments)
    return any(
        item.application_id is None or item.application_id == application_id
        for item in principal.assignments
    )


def application_action(action: str) -> bool:
    rule = RULES.get(action)
    return rule is not None and rule.scope in {"application", "either"}


def authorize(
    principal: Principal | None,
    action: str,
    application_id: UUID | None = None,
) -> Decision:
    """Allow only an explicit active assignment. Every other path denies."""
    if not isinstance(principal, Principal):
        return _deny(action, application_id, "unauthenticated")
    if not principal.is_active:
        return _deny(action, application_id, "inactive")
    if action in PROHIBITED_ACTIONS:
        return _deny(action, application_id, "prohibited")
    rule = RULES.get(action)
    if rule is None:
        return _deny(action, application_id, "unknown_action")
    platform_check = rule.scope == "platform" or (rule.scope == "either" and application_id is None)
    if rule.scope == "platform" and application_id is not None:
        return _deny(action, application_id, "platform_only")
    if platform_check:
        matched = _roles_for(principal, None)
        if matched & set(rule.roles):
            return _allow(action, None)
        reason: DecisionReason = "role_denied" if _covers(principal, None) else "missing_assignment"
        return _deny(action, None, reason)
    if application_id is None:
        return _deny(action, None, "scope_required")
    matched = _roles_for(principal, application_id)
    if matched & set(rule.roles):
        return _allow(action, application_id)
    reason = "role_denied" if _covers(principal, application_id) else "missing_assignment"
    return _deny(action, application_id, reason)


def fail_closed(
    principal: Principal | None,
    action: str,
    application_id: UUID | None = None,
) -> bool:
    """Return true only for an explicit allow. Exceptions deny."""
    try:
        return authorize(principal, action, application_id).allowed is True
    except Exception:
        return False


def application_scope(principal: Principal | None, action: str) -> ApplicationScope:
    """None-like empty scope is not all applications. Check `unrestricted` first."""
    if not isinstance(principal, Principal) or not principal.is_active:
        return ApplicationScope()
    if action in PROHIBITED_ACTIONS or action not in RULES:
        return ApplicationScope()
    rule = RULES[action]
    if rule.scope == "platform":
        return ApplicationScope()
    if any(
        item.application_id is None and item.role in rule.roles for item in principal.assignments
    ):
        return ApplicationScope(unrestricted=True)
    identifiers = {
        item.application_id
        for item in principal.assignments
        if item.application_id is not None and item.role in rule.roles
    }
    return ApplicationScope(application_ids=tuple(sorted(identifiers, key=str)))


def select_visible(
    rows: list[dict], principal: Principal | None, action: str, *, key: str
) -> list[dict]:
    scope = application_scope(principal, action)
    if scope.unrestricted:
        return list(rows)
    allowed = set(scope.application_ids)
    visible: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        identifier = row.get(key)
        if identifier in allowed:
            visible.append(row)
    return visible


def audit_actor(principal: Principal) -> str:
    if not isinstance(principal, Principal):
        raise IdentityError("Audit actor is unavailable.")
    return f"subject:{principal.subject_id}"


def operation_actor(principal: Principal, client_actor: str | None = None) -> str:
    """Ignore any actor supplied by the client, including `local-developer`."""
    del client_actor
    return audit_actor(principal)


_SENSITIVE_KEY = (
    "token",
    "token_hash",
    "pepper",
    "password",
    "secret",
    "authorization",
    "credential",
)


def redact(value: object) -> object:
    if isinstance(value, dict):
        cleaned: dict[object, object] = {}
        for key, item in value.items():
            if any(part in str(key).lower() for part in _SENSITIVE_KEY):
                continue
            cleaned[key] = redact(item)
        return cleaned
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and "wdn_" in value:
        return "[redacted]"
    return value


def audit_event(
    principal: Principal,
    *,
    entity_id: UUID,
    action: str,
    detail: dict | None = None,
) -> dict[str, object]:
    return {
        "entity_id": str(entity_id),
        "actor": audit_actor(principal),
        "action": action,
        "detail": redact(detail or {}),
    }


def build_principal(
    subject_id: UUID,
    *,
    is_active: bool,
    assignments: tuple[Assignment, ...] | list[Assignment],
    authentication_method: AuthenticationMethod,
) -> Principal:
    return Principal(
        subject_id=subject_id,
        is_active=is_active,
        authentication_method=authentication_method,
        assignments=tuple(assignments),
    )
