from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from alaira_warden.agents.demo import run_guided_demo
from alaira_warden.agents.response import (
    close_case,
    compose_plan,
    decide_approval,
    prepare_patch,
    record_validation,
    report,
)
from alaira_warden.agents.roster import public_roster
from alaira_warden.agents.traces import emit, for_case, recent
from alaira_warden.identity import audit_actor, enforce_application, enforce_platform
from alaira_warden.integration.auth import Actor
from alaira_warden.repository import Repository


class ApprovalBody(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    artifact_kind: Literal["plan", "patch"]
    decision: Literal["approved", "rejected"]
    justification: str = Field(min_length=10, max_length=2000)


class ClosureBody(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    outcome: Literal["not_affected", "discarded", "risk_accepted", "cancelled"]
    justification: str = Field(min_length=10, max_length=2000)


def create_agent_router(get_repository):
    router = APIRouter(prefix="/api", tags=["agents"])
    Store = Annotated[Repository, Depends(get_repository)]

    def case(store, principal, identifier, action):
        row = store.investigation(identifier)
        if not row:
            raise HTTPException(404, "Not found.")
        enforce_application(principal, action, row["application_id"], lambda _: True)
        return row

    @router.get("/agents")
    def roster():
        return {"crew": public_roster(), "mocks_are_labeled": True}

    @router.get("/agents/activity")
    def activity(store: Store, principal: Actor):
        enforce_platform(principal, "settings.manage")
        return recent(store.settings)

    @router.get("/investigations/{identifier}/agents")
    def timeline(identifier: UUID, store: Store, principal: Actor):
        case(store, principal, identifier, "investigation.read")
        return for_case(store.settings, identifier)

    @router.post("/demo/run", status_code=201)
    def demo(store: Store, principal: Actor):
        enforce_platform(principal, "settings.manage")
        return run_guided_demo(store.settings, actor=audit_actor(principal))

    @router.post("/investigations/{identifier}/plan", status_code=201)
    def plan(identifier: UUID, store: Store, principal: Actor):
        case(store, principal, identifier, "investigation.review")
        try:
            return compose_plan(
                store.settings, investigation_id=identifier, actor=audit_actor(principal)
            )
        except ValueError as error:
            raise HTTPException(409, str(error)) from None

    @router.post("/investigations/{identifier}/patch", status_code=201)
    def patch(identifier: UUID, store: Store, principal: Actor):
        row = case(store, principal, identifier, "investigation.review")
        enforce_application(principal, "patch.prepare", row["application_id"], lambda _: True)
        try:
            return prepare_patch(
                store.settings, investigation_id=identifier, actor=audit_actor(principal)
            )
        except ValueError as error:
            raise HTTPException(409, str(error)) from None

    @router.post("/investigations/{identifier}/validate", status_code=201)
    def validate(identifier: UUID, store: Store, principal: Actor):
        case(store, principal, identifier, "investigation.review")
        try:
            return record_validation(
                store.settings, investigation_id=identifier, actor=audit_actor(principal)
            )
        except ValueError as error:
            raise HTTPException(409, str(error)) from None

    @router.post("/investigations/{identifier}/approval", status_code=201)
    def approval(identifier: UUID, payload: ApprovalBody, store: Store, principal: Actor):
        row = case(store, principal, identifier, "investigation.read")
        enforce_application(principal, "approval.decide", row["application_id"], lambda _: True)
        try:
            return decide_approval(
                store.settings,
                investigation_id=identifier,
                actor=audit_actor(principal),
                artifact_kind=payload.artifact_kind,
                decision=payload.decision,
                justification=payload.justification,
            )
        except ValueError as error:
            raise HTTPException(409, str(error)) from None

    @router.post("/investigations/{identifier}/close", status_code=201)
    def close(identifier: UUID, payload: ClosureBody, store: Store, principal: Actor):
        case(store, principal, identifier, "investigation.review")
        try:
            return close_case(
                store.settings,
                investigation_id=identifier,
                actor=audit_actor(principal),
                outcome=payload.outcome,
                justification=payload.justification,
            )
        except ValueError as error:
            raise HTTPException(409, str(error)) from None

    @router.get("/investigations/{identifier}/report")
    def export_report(identifier: UUID, store: Store, principal: Actor):
        case(store, principal, identifier, "investigation.read")
        return report(store.settings, identifier)

    def refuse(identifier, store, principal, summary: str):
        case(store, principal, identifier, "investigation.read")
        emit(
            store.settings,
            investigation_id=identifier,
            agent="guardian",
            stage="guard",
            status="blocked",
            summary=summary,
            detail={"prohibited": True},
        )
        raise HTTPException(403, summary)

    @router.post("/investigations/{identifier}/merge")
    def merge(identifier: UUID, store: Store, principal: Actor):
        refuse(identifier, store, principal, "Merge is prohibited in the MVP.")

    @router.post("/investigations/{identifier}/deploy")
    def deploy(identifier: UUID, store: Store, principal: Actor):
        refuse(identifier, store, principal, "Deploy is prohibited in the MVP.")

    @router.post("/investigations/{identifier}/secrets")
    def secrets(identifier: UUID, store: Store, principal: Actor):
        refuse(identifier, store, principal, "Secret manipulation is prohibited in the MVP.")

    return router
