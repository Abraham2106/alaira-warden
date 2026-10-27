"""FastAPI dependencies. This router is not mounted on the global application."""

import json
from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from alaira_warden.identity.errors import (
    AuthenticationRequired,
    IdentityConfigurationError,
    IdentityConflict,
    IdentityReferenceError,
    IdentityRejected,
    PermissionDenied,
)
from alaira_warden.identity.principal import (
    Principal,
    application_action,
    authorize,
)
from alaira_warden.identity.services import (
    Authenticator,
    IdentitySettings,
    SubjectDraft,
    create_subject,
    issue_subject_credential,
    list_identity_subjects,
    list_subject_credentials,
    revoke_subject_credential,
    set_subject_active,
)
from alaira_warden.identity.store import IdentityStore


def read_bearer(request: Request) -> str | None:
    header = request.headers.get("authorization")
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    token = value.strip()
    if scheme.lower() != "bearer" or not token or " " in token:
        return None
    return token


def application_scope_id(*, path_id: UUID, body_id: UUID | None = None) -> UUID:
    """The path identifier is the resource. A body copy cannot move the scope."""
    del body_id
    return path_id


def _denied(decision_reason: str, action: str, application_id: UUID | None) -> HTTPException:
    if decision_reason == "unauthenticated":
        return HTTPException(
            401, "Authentication required.", headers={"WWW-Authenticate": "Bearer"}
        )
    if (
        decision_reason == "missing_assignment"
        and application_id is not None
        and application_action(action)
    ):
        return HTTPException(404, "Not found.")
    return HTTPException(403, "Forbidden.")


def enforce_application(
    principal: Principal | None,
    action: str,
    application_id: UUID,
    exists: Callable[[UUID], bool] | None,
) -> None:
    """Call the exists callback only after an explicit allow, so other scopes are not read."""
    decision = authorize(principal, action, application_id)
    if decision.allowed is not True:
        raise _denied(decision.reason, action, application_id)
    if not application_action(action):
        return
    if exists is None:
        raise HTTPException(503, "Identity policy is incomplete.")
    try:
        found = exists(application_id)
    except Exception:
        raise HTTPException(503, "Identity store unavailable.") from None
    if found is not True:
        raise HTTPException(404, "Not found.")


def enforce_platform(principal: Principal | None, action: str) -> None:
    decision = authorize(principal, action, None)
    if decision.allowed is not True:
        raise _denied(decision.reason, action, None)


class IdentityAuth:
    def __init__(self, store: IdentityStore, settings: IdentitySettings) -> None:
        self.store = store
        self.settings = settings
        self.authenticator = Authenticator(store, settings)

    def require_principal(self, request: Request) -> Principal:
        try:
            principal = self.authenticator.authenticate(read_bearer(request))
        except AuthenticationRequired:
            raise HTTPException(
                401, "Authentication required.", headers={"WWW-Authenticate": "Bearer"}
            ) from None
        except IdentityConfigurationError:
            raise HTTPException(503, "Identity configuration is incomplete.") from None
        except Exception:
            raise HTTPException(503, "Identity store unavailable.") from None
        if not principal.is_active:
            raise HTTPException(403, "Forbidden.")
        return principal


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, PermissionDenied):
        return HTTPException(403, "Forbidden.")
    if isinstance(exc, IdentityConflict):
        return HTTPException(409, "The request conflicts with an existing record.")
    if isinstance(exc, IdentityRejected):
        return HTTPException(422, "The request was rejected.")
    if isinstance(exc, IdentityReferenceError):
        return HTTPException(404, "Not found.")
    return HTTPException(503, "Identity store unavailable.")


class CredentialBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=120)


class StatusBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool


async def _json_body(request: Request) -> object:
    raw = await request.body()
    if not raw:
        raise HTTPException(422, "The request was rejected.")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(422, "The request was rejected.") from None


def _body(model: type[BaseModel], payload: object) -> BaseModel:
    try:
        return model.model_validate(payload)
    except ValidationError:
        raise HTTPException(422, "The request was rejected.") from None


def no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def create_identity_router(auth: IdentityAuth) -> APIRouter:
    """Admin identity routes. Mount them only inside an already authorized server process."""
    router = APIRouter(prefix="/api/identity", tags=["identity"], dependencies=[Depends(no_store)])

    @router.get("/session")
    def session(
        principal: Annotated[Principal, Depends(auth.require_principal)],
    ) -> dict[str, object]:
        return principal.public_dict()

    @router.get("/subjects")
    def subjects(
        principal: Annotated[Principal, Depends(auth.require_principal)],
    ) -> list[dict[str, object]]:
        try:
            return [item.public_dict() for item in list_identity_subjects(auth.store, principal)]
        except Exception as exc:
            raise _http_error(exc) from None

    @router.post("/subjects", status_code=201)
    async def subjects_create(
        request: Request,
        principal: Annotated[Principal, Depends(auth.require_principal)],
    ) -> dict[str, object]:
        enforce_platform(principal, "settings.manage")
        body = _body(SubjectDraft, await _json_body(request))
        try:
            created = create_subject(
                auth.store,
                principal,
                display_name=body.display_name,
                assignments=body.assignments,
            )
        except Exception as exc:
            raise _http_error(exc) from None
        return created.public_dict()

    @router.post("/subjects/{subject_id}/credentials", status_code=201)
    async def credentials_issue(
        subject_id: UUID,
        request: Request,
        principal: Annotated[Principal, Depends(auth.require_principal)],
    ) -> dict[str, str]:
        enforce_platform(principal, "settings.manage")
        body = _body(CredentialBody, await _json_body(request))
        try:
            issued = issue_subject_credential(
                auth.store,
                principal,
                subject_id,
                pepper=auth.settings.pepper_bytes(),
                label=body.label,
            )
        except Exception as exc:
            raise _http_error(exc) from None
        return {
            "credential_id": str(issued.credential_id),
            "subject_id": str(issued.subject_id),
            "token": issued.reveal_token(),
        }

    @router.get("/subjects/{subject_id}/credentials")
    def credentials_list(
        subject_id: UUID,
        principal: Annotated[Principal, Depends(auth.require_principal)],
    ) -> list[dict[str, object]]:
        try:
            rows = list_subject_credentials(auth.store, principal, subject_id)
        except Exception as exc:
            raise _http_error(exc) from None
        return [row.public_dict() for row in rows]

    @router.post("/credentials/{credential_id}/revocation")
    def credentials_revoke(
        credential_id: UUID,
        principal: Annotated[Principal, Depends(auth.require_principal)],
    ) -> dict[str, object]:
        try:
            revoked = revoke_subject_credential(auth.store, principal, credential_id)
        except Exception as exc:
            raise _http_error(exc) from None
        return revoked.public_dict()

    @router.post("/subjects/{subject_id}/status")
    async def subjects_status(
        subject_id: UUID,
        request: Request,
        principal: Annotated[Principal, Depends(auth.require_principal)],
    ) -> dict[str, bool]:
        enforce_platform(principal, "settings.manage")
        body = _body(StatusBody, await _json_body(request))
        try:
            set_subject_active(auth.store, principal, subject_id, is_active=body.is_active)
        except Exception as exc:
            raise _http_error(exc) from None
        return {"is_active": body.is_active}

    return router
