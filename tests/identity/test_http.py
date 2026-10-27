"""HTTP negatives: 401 unauthenticated, 403 wrong role, 404 outside the assigned application."""

from typing import Annotated
from uuid import UUID, uuid4

import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict, SecretStr

from alaira_warden.identity.credentials import generate_token
from alaira_warden.identity.http import (
    IdentityAuth,
    application_scope_id,
    create_identity_router,
    enforce_application,
    enforce_platform,
)
from alaira_warden.identity.principal import Assignment, Principal, operation_actor
from alaira_warden.identity.services import (
    Authenticator,
    IdentitySettings,
    create_subject,
    issue_subject_credential,
    provision_initial_administrator,
)
from alaira_warden.identity.store import MemoryIdentityStore
from tests.identity.conftest import PEPPER, PEPPER_TEXT

APP_A = uuid4()
APP_B = uuid4()
MARKER = "visible-only-when-authorized"


class ApprovalBody(BaseModel):
    model_config = ConfigDict(extra="allow")

    application_id: str | None = None
    roles: list[str] | None = None
    subject_id: str | None = None
    actor: str | None = None


def _settings() -> IdentitySettings:
    return IdentitySettings(
        credential_pepper=SecretStr(PEPPER_TEXT),
        environment="test",
        shared_development_token=SecretStr("explicit-dev-token"),
    )


def _subject(store, principal, name, role, application_id) -> UUID:
    created = create_subject(
        store,
        principal,
        display_name=name,
        assignments=(Assignment(role=role, application_id=application_id),),
    )
    return created.subject_id


def _world():
    store = MemoryIdentityStore()
    settings = _settings()
    admin = provision_initial_administrator(store, display_name="Ada Admin", pepper=PEPPER)
    auth = IdentityAuth(store, settings)
    admin_principal = auth.authenticator.authenticate(admin.reveal_token())
    developer = issue_subject_credential(
        store,
        admin_principal,
        _subject(store, admin_principal, "Dev", "desarrollador", APP_A),
        pepper=PEPPER,
        label="dev-laptop",
    )
    approver = issue_subject_credential(
        store,
        admin_principal,
        _subject(store, admin_principal, "Approver", "aprobador", APP_A),
        pepper=PEPPER,
        label="approver-laptop",
    )
    auditor = issue_subject_credential(
        store,
        admin_principal,
        _subject(store, admin_principal, "Auditor", "auditor", APP_A),
        pepper=PEPPER,
        label="auditor-laptop",
    )
    app = FastAPI()
    app.include_router(create_identity_router(auth))
    seen: list[UUID] = []

    @app.post("/api/applications/{application_id}/approvals")
    async def decide_approval(
        application_id: UUID,
        request: Request,
        principal: Annotated[Principal, Depends(auth.require_principal)],
    ):
        payload = ApprovalBody.model_validate(await request.json())
        scope = application_scope_id(
            path_id=application_id,
            body_id=UUID(payload.application_id) if payload.application_id else None,
        )

        def exists(identifier: UUID) -> bool:
            seen.append(identifier)
            return identifier in {APP_A, APP_B}

        enforce_application(principal, "approval.decide", scope, exists)
        return {
            "marker": MARKER,
            "actor": operation_actor(principal, client_actor=payload.actor or "local-developer"),
        }

    @app.post("/api/applications")
    def create_application(
        principal: Annotated[Principal, Depends(auth.require_principal)],
    ):
        enforce_platform(principal, "application.create")
        return {"marker": MARKER}

    return {
        "client": TestClient(app),
        "store": store,
        "seen": seen,
        "admin": admin.reveal_token(),
        "developer": developer.reveal_token(),
        "approver": approver.reveal_token(),
        "auditor": auditor.reveal_token(),
        "admin_id": str(admin.subject_id),
    }


def test_missing_invalid_and_foreign_credentials_are_401():
    world = _world()
    client = world["client"]
    assert client.get("/api/identity/session").status_code == 401
    basic = client.get(
        "/api/identity/session", headers={"Authorization": "Basic " + world["admin"]}
    )
    assert basic.status_code == 401
    assert world["admin"] not in basic.text
    forged = client.get(
        "/api/identity/session",
        headers={"Authorization": "Bearer " + world["developer"]},
        params={"subject_id": world["admin_id"]},
    )
    assert forged.status_code == 200
    assert forged.json()["subject_id"] != world["admin_id"]
    assert forged.json()["roles"] == ["desarrollador"]
    assert world["developer"] not in forged.text
    assert "token_hash" not in forged.text
    shared = client.get(
        "/api/identity/session",
        headers={
            "Authorization": "Bearer explicit-dev-token",
            "X-Roles": "administrador",
            "X-Subject-Id": world["admin_id"],
        },
    )
    assert shared.status_code == 401
    assert "administrador" not in shared.text


def test_client_claims_do_not_change_the_decision_or_the_actor():
    world = _world()
    client = world["client"]
    headers = {"Authorization": "Bearer " + world["approver"]}
    response = client.post(
        f"/api/applications/{APP_A}/approvals",
        headers=headers,
        json={
            "application_id": str(APP_B),
            "roles": ["administrador"],
            "subject_id": world["admin_id"],
            "actor": "local-developer",
        },
    )
    assert response.status_code == 200
    assert response.json()["marker"] == MARKER
    assert response.json()["actor"].startswith("subject:")
    assert response.json()["actor"] != "local-developer"
    assert world["admin_id"] not in response.json()["actor"]
    denied = client.post(
        f"/api/applications/{APP_B}/approvals",
        headers=headers,
        json={"application_id": str(APP_A), "roles": ["administrador"], "actor": "local-developer"},
    )
    assert denied.status_code == 404
    assert MARKER not in denied.text
    assert str(APP_B) not in denied.text
    developer = client.post(
        f"/api/applications/{APP_A}/approvals",
        headers={"Authorization": "Bearer " + world["developer"]},
        json={"roles": ["aprobador"], "subject_id": world["admin_id"]},
    )
    assert developer.status_code == 403
    assert MARKER not in developer.text
    assert world["seen"] == [APP_A]


def test_auditor_cannot_mutate_and_credentials_are_not_echoed():
    world = _world()
    client = world["client"]
    auditor = {"Authorization": "Bearer " + world["auditor"]}
    created = client.post("/api/applications", headers=auditor)
    assert created.status_code == 403
    assert MARKER not in created.text
    approval = client.post(
        f"/api/applications/{APP_A}/approvals",
        headers=auditor,
        json={"actor": "local-developer"},
    )
    assert approval.status_code == 403
    assert MARKER not in approval.text
    assert client.get("/api/identity/subjects", headers=auditor).status_code == 403
    developer = {"Authorization": "Bearer " + world["developer"]}
    rejected = client.post(
        "/api/identity/subjects",
        headers=developer,
        json={"display_name": "Other", "roles": ["administrador"]},
    )
    assert rejected.status_code == 403
    assert "Ada Admin" not in rejected.text
    admin = {"Authorization": "Bearer " + world["admin"]}
    issued = client.post(
        f"/api/identity/subjects/{world['admin_id']}/credentials",
        headers=admin,
        json={"label": "wdn_should-not-echo", "token": world["admin"]},
    )
    assert issued.status_code == 422
    assert world["admin"] not in issued.text
    assert "wdn_should-not-echo" not in issued.text
    good = client.post(
        f"/api/identity/subjects/{world['admin_id']}/credentials",
        headers=admin,
        json={"label": "second-laptop"},
    )
    assert good.status_code == 201
    token = good.json()["token"]
    follow = client.get(f"/api/identity/subjects/{world['admin_id']}/credentials", headers=admin)
    assert token not in follow.text
    assert "token_hash" not in follow.text
    assert follow.headers["cache-control"] == "no-store"
    spoof = client.post(
        "/api/identity/subjects",
        headers=admin,
        json={
            "display_name": "Intruder",
            "subject_id": world["admin_id"],
            "roles": ["administrador"],
        },
    )
    assert spoof.status_code == 422
    assert world["admin"] not in spoof.text
    assert client.post("/api/identity/subjects", json={"display_name": "Nope"}).status_code == 401
    included = next(
        route for route in client.app.routes if type(route).__name__ == "_IncludedRouter"
    )
    paths = [getattr(route, "path", "") for route in included.original_router.routes]
    assert any(path.endswith("/session") for path in paths)
    assert not any("bootstrap" in path or "register" in path or "oauth" in path for path in paths)


def test_store_failure_is_not_authorization():
    class BrokenStore(MemoryIdentityStore):
        def resolve_credential(self, token: str, pepper: bytes):
            raise RuntimeError(f"down token={token} pepper={pepper!r} hash=deadbeef")

    token = generate_token()
    auth = IdentityAuth(BrokenStore(), _settings())
    app = FastAPI()
    app.include_router(create_identity_router(auth))
    response = TestClient(app).get(
        "/api/identity/session", headers={"Authorization": "Bearer " + token}
    )
    assert response.status_code == 503
    assert token not in response.text
    assert "deadbeef" not in response.text
    assert PEPPER_TEXT not in response.text
    assert "administrador" not in response.text


def test_exists_failure_and_out_of_scope_do_not_release_data():
    world = _world()
    settings = _settings()
    approver = Authenticator(world["store"], settings).authenticate(world["approver"])

    def explode(_identifier: UUID) -> bool:
        raise RuntimeError("title of application B and wdn_secret")

    with pytest.raises(HTTPException) as caught:
        enforce_application(approver, "approval.decide", APP_A, explode)
    assert caught.value.status_code == 503
    assert "wdn_" not in str(caught.value.detail)

    developer = Authenticator(world["store"], settings).authenticate(world["developer"])
    called: list[UUID] = []

    def should_not_run(identifier: UUID) -> bool:
        called.append(identifier)
        raise RuntimeError("secret-title")

    with pytest.raises(HTTPException) as hidden:
        enforce_application(developer, "approval.decide", APP_B, should_not_run)
    assert hidden.value.status_code == 404
    assert called == []
    assert hidden.value.detail == "Not found."
    with pytest.raises(HTTPException) as incomplete:
        enforce_application(approver, "approval.decide", APP_A, None)
    assert incomplete.value.status_code == 503
