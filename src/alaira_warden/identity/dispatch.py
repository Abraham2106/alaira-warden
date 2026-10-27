"""Decide whether a case may be sent to a model. This module does not call providers."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from alaira_warden.identity.principal import INVESTIGATION_READ, Principal, authorize

DispatchField = Literal["case_id", "finding_ids", "package_names", "versions"]
PERMITTED_FIELDS: frozenset[str] = frozenset(
    {"case_id", "finding_ids", "package_names", "versions"}
)


class ModelDispatchDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    reason: str
    application_id: UUID
    permitted_fields: tuple[str, ...] = ()


def authorize_model_dispatch(
    principal: Principal | None,
    application_id: UUID,
    *,
    policy: str = "deny",
    destination: str,
    approved_destinations: frozenset[str] = frozenset(),
    fields: tuple[str, ...] = (),
) -> ModelDispatchDecision:
    """Default policy is deny. An administrator does not bypass the destination policy."""
    denied = ModelDispatchDecision(
        allowed=False, reason="policy_denied", application_id=application_id
    )
    try:
        if policy != "allow_minimized":
            return denied
        if destination not in approved_destinations or not destination:
            return denied
        if not fields or any(field not in PERMITTED_FIELDS for field in fields):
            return denied
        decision = authorize(principal, INVESTIGATION_READ, application_id)
        if decision.allowed is not True:
            return ModelDispatchDecision(
                allowed=False,
                reason=decision.reason,
                application_id=application_id,
            )
        return ModelDispatchDecision(
            allowed=True,
            reason="allowed",
            application_id=application_id,
            permitted_fields=tuple(dict.fromkeys(fields)),
        )
    except Exception:
        return denied


def model_dispatch_allowed(
    principal: Principal | None,
    application_id: UUID,
    *,
    policy: str = "deny",
    destination: str,
    approved_destinations: frozenset[str] = frozenset(),
    fields: tuple[str, ...] = (),
) -> bool:
    try:
        return (
            authorize_model_dispatch(
                principal,
                application_id,
                policy=policy,
                destination=destination,
                approved_destinations=approved_destinations,
                fields=fields,
            ).allowed
            is True
        )
    except Exception:
        return False
