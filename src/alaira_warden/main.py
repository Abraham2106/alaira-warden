import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from alaira_warden import __version__
from alaira_warden.config import Settings, get_settings
from alaira_warden.db import SchemaNotReady
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
bearer = HTTPBearer(auto_error=False)


def require_token(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> None:
    expected = request.app.state.settings.warden_api_token.get_secret_value()
    if not expected:
        raise HTTPException(503, "Configure WARDEN_API_TOKEN to enable the development API.")
    if credentials is None or not secrets.compare_digest(
        credentials.credentials.encode(), expected.encode()
    ):
        raise HTTPException(401, "Invalid API token.", headers={"WWW-Authenticate": "Bearer"})


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

    @app.exception_handler(psycopg.Error)
    async def database_error(_request: Request, _exc: psycopg.Error):
        return JSONResponse(
            status_code=503, content={"detail": "Database unavailable or unmigrated."}
        )

    @app.get("/health/live", tags=["health"])
    def live():
        return {"status": "ok", "version": __version__}

    @app.get("/health/ready", tags=["health"])
    def ready(store: Store):
        try:
            store.ready()
        except (psycopg.Error, SchemaNotReady):
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "database": "unavailable_or_schema_mismatch"},
            )
        return {"status": "ready", "database": "ok"}

    api = APIRouter(prefix="/api", dependencies=[Depends(require_token)])

    @api.get("/integrations", tags=["integrations"])
    def integrations():
        return integration_status(settings)

    @api.get("/applications", response_model=list[Application], tags=["applications"])
    def applications(store: Store):
        return store.applications()

    @api.post("/applications", response_model=Application, status_code=201, tags=["applications"])
    def create_application(payload: ApplicationCreate, store: Store):
        return store.create_application(payload)

    @api.get("/investigations", response_model=list[Investigation], tags=["investigations"])
    def investigations(store: Store):
        return store.investigations()

    @api.post(
        "/investigations", response_model=Investigation, status_code=201, tags=["investigations"]
    )
    def create_investigation(payload: InvestigationCreate, store: Store):
        try:
            return store.create_investigation(payload)
        except psycopg.errors.ForeignKeyViolation as exc:
            raise HTTPException(404, "Application not found.") from exc

    @api.get("/investigations/{identifier}", response_model=Investigation, tags=["investigations"])
    def investigation(identifier: UUID, store: Store):
        case = store.investigation(identifier)
        if case is None:
            raise HTTPException(404, "Investigation not found.")
        return case

    @api.post("/investigations/{identifier}/preview", tags=["workflow"])
    def preview(identifier: UUID, store: Store):
        if store.investigation(identifier) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found.")
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
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    return app


app = create_app()
