from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from alaira_warden.config import Settings
from alaira_warden.db import connect
from alaira_warden.identity import (
    IdentityAuth,
    IdentitySettings,
    PostgresIdentityStore,
    Principal,
    audit_actor,
)
from alaira_warden.identity.credentials import is_well_formed
from alaira_warden.identity.http import read_bearer


def identity_settings(settings: Settings) -> IdentitySettings:
    return IdentitySettings(
        credential_pepper=settings.warden_identity_pepper,
        shared_development_token=settings.warden_api_token,
        environment=settings.warden_env,
    )


bearer = HTTPBearer(
    auto_error=False,
    scheme_name="IndividualCredential",
    description="Individual opaque wdn_ credential; shared development token is rejected.",
)


def get_identity_auth(
    request: Request, _credential: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]
):
    settings = request.app.state.settings
    try:
        identity = identity_settings(settings)
    except ValueError:
        raise HTTPException(503, "Identity configuration is incomplete.") from None
    if not is_well_formed(read_bearer(request) or ""):
        raise HTTPException(401, "Authentication required.", headers={"WWW-Authenticate": "Bearer"})
    with connect(settings) as connection:

        def audit(principal, identifier, action):
            connection.execute(
                "INSERT INTO audit_events(entity_id,actor,action) VALUES (%s,%s,%s)",
                (identifier, audit_actor(principal), action),
            )

        yield IdentityAuth(PostgresIdentityStore(connection), identity, audit=audit)


def get_principal(
    request: Request, auth: Annotated[IdentityAuth, Depends(get_identity_auth)]
) -> Principal:
    return auth.require_principal(request)


Actor = Annotated[Principal, Depends(get_principal)]
