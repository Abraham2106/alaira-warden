"""Guided crew demo. Uses fixtures and a labeled Nightshift mock. No sponsor calls."""

from uuid import uuid4

from alaira_warden.agents.fixtures import DEMO_GHSA, DemoTransport
from alaira_warden.agents.mocks import MockNightshift
from alaira_warden.agents.response import (
    compose_plan,
    prepare_patch,
    record_validation,
    report,
)
from alaira_warden.agents.traces import emit, for_case
from alaira_warden.integration.services import ProductServices
from alaira_warden.models import ApplicationCreate, InvestigationCreate
from alaira_warden.orchestration.runtime import RunRequest
from alaira_warden.repository import Repository


def run_guided_demo(settings, *, actor: str) -> dict:
    suffix = uuid4().hex[:8]
    store = Repository(settings)
    demo_settings = settings.model_copy(update={"warden_model_dispatch_policy": "allow_minimized"})
    services = ProductServices(demo_settings, transport=DemoTransport(), meterless=MockNightshift())
    application = store.create_application(
        ApplicationCreate(
            name=f"Demo Warden {suffix}",
            repository=f"demo-org/warden-{suffix}",
            owner="Hackathon demo",
            organization="demo-org",
            criticality="high",
            environments=["production"],
        ),
        actor=actor,
    )
    case = store.create_investigation(
        InvestigationCreate(
            application_id=application["id"],
            title=f"lodash prototype pollution {DEMO_GHSA}",
            source_url=f"https://github.com/advisories/{DEMO_GHSA}",
            description="Guided agent demo. Synthetic sources. Sponsors not contacted.",
        ),
        actor=actor,
    )
    emit(
        settings,
        investigation_id=case["id"],
        agent="warden",
        stage="intake",
        status="started",
        summary="Crew assembled for a labeled synthetic investigation.",
        detail={"synthetic": True, "sponsors_contacted": False},
    )
    snapshot = services.refresh(application, "HEAD", actor)
    emit(
        settings,
        investigation_id=case["id"],
        agent="cartographer",
        stage="inventory",
        status="handed_off",
        summary="Pinned npm snapshot from the demo fixture lockfile.",
        detail={"snapshot_id": str(snapshot["id"]), "synthetic": True},
    )
    run_id = services.runtime().start(
        RunRequest(
            application_id=application["id"],
            investigation_id=case["id"],
            request_key=uuid4(),
            subject_id=actor,
            snapshot_id=snapshot["id"],
            advisory_identifier=DEMO_GHSA,
            data_mode=settings.warden_data_mode,
            stage_seconds=60,
            max_active_seconds=240,
        )
    )
    emit(
        settings,
        investigation_id=case["id"],
        agent="warden",
        stage="dispatch",
        status="started",
        summary="Three bounded stages: inventory, sources, correlation.",
        run_id=run_id,
        detail={"synthetic": True},
    )
    states = []
    for _ in range(3):
        states.append(services.runtime().advance(run_id, application["id"]))
    plan = compose_plan(settings, investigation_id=case["id"], actor=actor)
    try:
        patch = prepare_patch(settings, investigation_id=case["id"], actor=actor)
        validation = record_validation(settings, investigation_id=case["id"], actor=actor)
    except ValueError:
        patch, validation = None, None
    emit(
        settings,
        investigation_id=case["id"],
        agent="warden",
        stage="demo",
        status="decided",
        summary="Demo finished. Nightshift was not contacted. Merge remains prohibited.",
        run_id=run_id,
        detail={"synthetic": True, "nightshift_verified": False},
    )
    return {
        "synthetic": True,
        "credentials_used": False,
        "sponsors_verified": False,
        "nightshift_deployment_verified": False,
        "application_id": application["id"],
        "investigation_id": case["id"],
        "run_id": run_id,
        "snapshot_id": snapshot["id"],
        "workflow": states[-1] if states else None,
        "plan": plan,
        "patch": patch,
        "validation": validation,
        "events": for_case(settings, case["id"]),
        "report": report(settings, case["id"]),
    }
