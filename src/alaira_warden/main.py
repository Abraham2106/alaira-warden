from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from alaira_warden import __version__
from alaira_warden.agents.http import create_agent_router
from alaira_warden.agents.roster import public_roster
from alaira_warden.agents.traces import public_recent
from alaira_warden.config import Settings, get_settings
from alaira_warden.db import SchemaNotReady
from alaira_warden.hmem import HMEM
from alaira_warden.identity import (
    audit_actor,
    create_identity_router,
    enforce_application,
    enforce_platform,
)
from alaira_warden.integration.auth import Actor, get_identity_auth, identity_settings
from alaira_warden.integration.routes import create_product_router
from alaira_warden.integrations import integration_status
from alaira_warden.models import (
    Application,
    ApplicationCreate,
    Investigation,
    InvestigationCreate,
)
from alaira_warden.observability import instrument
from alaira_warden.repository import Repository
from alaira_warden.workflow import build_workflow

STATIC = Path(__file__).parent / "static"


def get_repository(request: Request) -> Repository:
    return Repository(request.app.state.settings)


Store = Annotated[Repository, Depends(get_repository)]


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        yield
        application.state.telemetry.shutdown()

    app = FastAPI(title="ALAIRA Warden", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.workflow = build_workflow()
    app.state.telemetry = instrument(app, settings)
    persist = settings.warden_hmem_persist_dir.strip() or None
    app.state.hmem = HMEM({"actor": "warden", "persistDir": persist})

    @app.exception_handler(psycopg.Error)
    async def database_error(_request: Request, _exc: psycopg.Error):
        return JSONResponse(
            status_code=503, content={"detail": "Database unavailable or unmigrated."}
        )

    @app.get("/health/live", tags=["health"])
    def live():
        return {"status": "ok", "version": __version__}

    @app.get("/agents", tags=["agents"])
    def agents_public():
        return {
            "crew": public_roster(),
            "mocks_are_labeled": True,
            "nightshift": "Host hotspot or labeled mock. Never NVIDIA-direct.",
        }

    @app.get("/agents/activity", tags=["agents"])
    def agents_activity_public():
        try:
            events = public_recent(settings)
        except (psycopg.Error, SchemaNotReady, OSError):
            events = []
        return {"events": events, "mocks_are_labeled": True}

    @app.get("/health/ready", tags=["health"])
    def ready(store: Store):
        try:
            identity_settings(settings)
            store.ready()
        except (psycopg.Error, SchemaNotReady, ValueError):
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "database": "unavailable_or_schema_mismatch"},
            )
        return {"status": "ready", "database": "ok"}

    api = APIRouter(prefix="/api")

    @api.get("/integrations", tags=["integrations"])
    def integrations(principal: Actor, store: Store):
        enforce_platform(principal, "settings.manage")
        return integration_status(settings, store.integration_checks())

    @api.get("/applications", response_model=list[Application], tags=["applications"])
    def applications(store: Store, principal: Actor):
        return store.applications(principal)

    @api.post("/applications", response_model=Application, status_code=201, tags=["applications"])
    def create_application(payload: ApplicationCreate, store: Store, principal: Actor):
        enforce_platform(principal, "application.create")
        return store.create_application(payload, actor=audit_actor(principal))

    @api.get("/investigations", response_model=list[Investigation], tags=["investigations"])
    def investigations(store: Store, principal: Actor):
        return store.investigations(principal)

    @api.post(
        "/investigations", response_model=Investigation, status_code=201, tags=["investigations"]
    )
    def create_investigation(payload: InvestigationCreate, store: Store, principal: Actor):
        enforce_application(
            principal,
            "investigation.create",
            payload.application_id,
            lambda identifier: store.application(identifier) is not None,
        )
        try:
            return store.create_investigation(payload, actor=audit_actor(principal))
        except psycopg.errors.ForeignKeyViolation as exc:
            raise HTTPException(404, "Application not found.") from exc

    @api.get("/investigations/{identifier}", response_model=Investigation, tags=["investigations"])
    def investigation(identifier: UUID, store: Store, principal: Actor):
        case = store.investigation(identifier)
        if case is None:
            raise HTTPException(404, "Investigation not found.")
        enforce_application(principal, "investigation.read", case["application_id"], lambda _: True)
        return case

    @api.post("/investigations/{identifier}/preview", tags=["workflow"])
    def preview(identifier: UUID, store: Store, principal: Actor):
        investigation(identifier, store, principal)
        return app.state.workflow.invoke(
            {
                "case_id": str(identifier),
                "mode": "scaffold_preview",
                "status": "detected",
                "stages": [],
                "blockers": [],
            }
        )

    app.include_router(api)
    app.include_router(create_identity_router(get_identity_auth))
    app.include_router(create_product_router(get_repository))
    app.include_router(create_agent_router(get_repository))
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path == "/" or request.url.path.startswith("/static/"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self'; object-src 'none'; "
                "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
            )
        if request.url.path.startswith("/api/") or request.url.path.startswith("/agents"):
            response.headers["Cache-Control"] = "no-store"
        return response

    return app


app = create_app()
