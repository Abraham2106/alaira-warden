"""Deterministic plan, labeled patch, honest validation, human approval."""

import hashlib
import json
from uuid import uuid4

from psycopg.types.json import Jsonb

from alaira_warden.agents import traces
from alaira_warden.db import connect


def _hash(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def compose_plan(settings, *, investigation_id, actor: str) -> dict:
    with connect(settings) as connection:
        assessments = connection.execute(
            "SELECT payload FROM assessments WHERE investigation_id=%s "
            "ORDER BY created_at DESC LIMIT 5",
            (investigation_id,),
        ).fetchall()
        if not assessments:
            raise ValueError("Correlate the case before composing a plan")
        exposures = [item["payload"].get("exposure") for item in assessments]
        exposure = next(
            (
                value
                for value in ("confirmed", "potential", "undetermined", "not_affected")
                if value in exposures
            ),
            "undetermined",
        )
        findings = [
            finding for item in assessments for finding in item["payload"].get("findings") or []
        ]
        packages = sorted(
            {
                f"{item.get('package_name')}@{item.get('resolved_version')}"
                for item in findings
                if item.get("package_name")
            }
        )
        version_hit = any(item.get("version_affected") is True for item in findings)
        if exposure == "not_affected":
            action = "abstain"
            justification = "No affected version in the pinned snapshot."
        elif version_hit or exposure in {"confirmed", "potential"}:
            action = "update_dependency"
            justification = (
                "A resolved npm version matches the advisory range. "
                "Deployment execution is not fully proven; keep exposure unconfirmed until review."
            )
        else:
            action = "request_information"
            justification = "Inventory or conditions are incomplete."
        payload = {
            "action": action,
            "exposure": exposure,
            "packages": packages[:20],
            "validation": ["npm ci", "project tests", "syft", "trivy", "osv-scanner"],
            "rollback": "Revert the lockfile change on the feature branch.",
            "risks": ["Transitive lodash may remain until the parent is bumped."],
            "justification": justification,
            "compromise_follow_up": (
                "If historical execution or secret exposure is possible, review access "
                "and rotate credentials through the organization's process. Updating the "
                "package does not close that finding."
            ),
            "synthetic": False,
            "model_is_evidence": False,
        }
        digest = _hash(payload)
        identifier = uuid4()
        connection.execute(
            "INSERT INTO investigation_plans(id,investigation_id,actor,payload,content_hash) "
            "VALUES (%s,%s,%s,%s,%s)",
            (identifier, investigation_id, actor, Jsonb(payload), digest),
        )
    traces.emit(
        settings,
        investigation_id=investigation_id,
        agent="planner",
        stage="plan",
        status="decided",
        summary=f"Plan {action} for exposure {exposure}.",
        detail={"plan_id": str(identifier), "action": action},
    )
    return {"id": identifier, "payload": payload, "content_hash": digest}


def prepare_patch(settings, *, investigation_id, actor: str) -> dict:
    with connect(settings) as connection:
        plan = connection.execute(
            "SELECT id,payload,content_hash FROM investigation_plans "
            "WHERE investigation_id=%s ORDER BY created_at DESC LIMIT 1",
            (investigation_id,),
        ).fetchone()
        if not plan:
            raise ValueError("Compose a plan before preparing a patch")
        if plan["payload"].get("action") != "update_dependency":
            traces.emit(
                settings,
                investigation_id=investigation_id,
                agent="patchwright",
                stage="engineering",
                status="skipped",
                summary="No lockfile change: the plan is not an update.",
                detail={"plan_id": str(plan["id"])},
            )
            raise ValueError("The selected plan does not authorize a patch")
        payload = {
            "base_ref": "HEAD",
            "branch": f"warden/{investigation_id}",
            "isolated": True,
            "merge_forbidden": True,
            "files": ["package.json", "package-lock.json"],
            "diff": (
                "--- a/package-lock.json\n+++ b/package-lock.json\n"
                '@@ lodash @@\n-    "version": "4.17.20"\n+    "version": "4.17.21"\n'
            ),
            "synthetic": True,
            "execution": "not_started",
            "note": "Labeled demo diff. No git branch was created and merge is prohibited.",
        }
        digest = _hash(payload)
        identifier = uuid4()
        connection.execute(
            "INSERT INTO investigation_patches"
            "(id,investigation_id,plan_id,actor,payload,content_hash) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (identifier, investigation_id, plan["id"], actor, Jsonb(payload), digest),
        )
        connection.execute(
            "UPDATE investigation_approvals SET valid=FALSE WHERE investigation_id=%s "
            "AND artifact_kind='patch' AND valid=TRUE",
            (investigation_id,),
        )
    traces.emit(
        settings,
        investigation_id=investigation_id,
        agent="patchwright",
        stage="engineering",
        status="decided",
        summary="Isolated lockfile diff prepared. Merge remains prohibited.",
        detail={"patch_id": str(identifier), "synthetic": True},
    )
    return {"id": identifier, "payload": payload, "content_hash": digest}


def record_validation(settings, *, investigation_id, actor: str) -> dict:
    with connect(settings) as connection:
        patch = connection.execute(
            "SELECT id FROM investigation_patches WHERE investigation_id=%s "
            "ORDER BY created_at DESC LIMIT 1",
            (investigation_id,),
        ).fetchone()
        if not patch:
            raise ValueError("Prepare a patch before validation")
        payload = {
            "commit": None,
            "results": [
                {
                    "tool": "project_tests",
                    "status": "not_executed",
                    "reason": "no_isolated_checkout",
                },
                {"tool": "syft", "status": "not_executed", "reason": "image_not_configured"},
                {"tool": "trivy", "status": "not_executed", "reason": "image_not_configured"},
                {"tool": "osv-scanner", "status": "not_executed", "reason": "image_not_configured"},
            ],
            "overall": "not_executed",
            "approved": False,
            "synthetic": True,
        }
        identifier = uuid4()
        connection.execute(
            "INSERT INTO investigation_validations"
            "(id,investigation_id,patch_id,actor,payload) VALUES (%s,%s,%s,%s,%s)",
            (identifier, investigation_id, patch["id"], actor, Jsonb(payload)),
        )
    traces.emit(
        settings,
        investigation_id=investigation_id,
        agent="verifier",
        stage="validation",
        status="blocked",
        summary="Validation not executed. A missing scanner is not an approval.",
        detail={"validation_id": str(identifier), "overall": "not_executed"},
    )
    return {"id": identifier, "payload": payload}


def decide_approval(
    settings,
    *,
    investigation_id,
    actor: str,
    artifact_kind: str,
    decision: str,
    justification: str,
) -> dict:
    if artifact_kind not in {"plan", "patch"} or decision not in {"approved", "rejected"}:
        raise ValueError("Invalid approval")
    with connect(settings) as connection:
        if artifact_kind == "plan":
            artifact = connection.execute(
                "SELECT id,content_hash FROM investigation_plans WHERE investigation_id=%s "
                "ORDER BY created_at DESC LIMIT 1",
                (investigation_id,),
            ).fetchone()
        else:
            artifact = connection.execute(
                "SELECT id,content_hash FROM investigation_patches WHERE investigation_id=%s "
                "ORDER BY created_at DESC LIMIT 1",
                (investigation_id,),
            ).fetchone()
        if not artifact:
            raise ValueError("Artifact not found")
        identifier = uuid4()
        connection.execute(
            "UPDATE investigation_approvals SET valid=FALSE WHERE investigation_id=%s "
            "AND artifact_kind=%s AND valid=TRUE",
            (investigation_id, artifact_kind),
        )
        connection.execute(
            "INSERT INTO investigation_approvals"
            "(id,investigation_id,artifact_kind,artifact_id,artifact_hash,decision,"
            "actor,justification,valid) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,TRUE)",
            (
                identifier,
                investigation_id,
                artifact_kind,
                artifact["id"],
                artifact["content_hash"],
                decision,
                actor,
                justification.strip(),
            ),
        )
    traces.emit(
        settings,
        investigation_id=investigation_id,
        agent="guardian",
        stage="approval",
        status="decided",
        summary=f"Human {decision} the {artifact_kind}. Merge is still prohibited.",
        detail={"approval_id": str(identifier), "decision": decision},
    )
    return {
        "id": identifier,
        "decision": decision,
        "artifact_kind": artifact_kind,
        "artifact_id": artifact["id"],
        "valid": True,
    }


def close_case(settings, *, investigation_id, actor: str, outcome: str, justification: str) -> dict:
    if outcome not in {"not_affected", "discarded", "risk_accepted", "cancelled"}:
        raise ValueError("Invalid closure")
    status = "cancelled" if outcome == "cancelled" else "closed"
    identifier = uuid4()
    with connect(settings) as connection:
        connection.execute(
            "INSERT INTO investigation_closures"
            "(id,investigation_id,outcome,actor,justification) VALUES (%s,%s,%s,%s,%s)",
            (identifier, investigation_id, outcome, actor, justification.strip()),
        )
        connection.execute(
            "UPDATE investigations SET status=%s WHERE id=%s",
            (status, investigation_id),
        )
    traces.emit(
        settings,
        investigation_id=investigation_id,
        agent="guardian",
        stage="closure",
        status="decided",
        summary=f"Case {status} as {outcome}.",
        detail={"closure_id": str(identifier), "outcome": outcome},
    )
    return {"id": identifier, "status": status, "outcome": outcome}


def report(settings, investigation_id) -> dict:
    with connect(settings) as connection:
        case = connection.execute(
            "SELECT * FROM investigations WHERE id=%s", (investigation_id,)
        ).fetchone()
        evidence = connection.execute(
            "SELECT source_url,excerpt,confidence FROM evidence WHERE investigation_id=%s "
            "ORDER BY retrieved_at DESC LIMIT 20",
            (investigation_id,),
        ).fetchall()
        assessments = connection.execute(
            "SELECT payload,data_layer FROM assessments WHERE investigation_id=%s "
            "ORDER BY created_at DESC LIMIT 5",
            (investigation_id,),
        ).fetchall()
        plan = connection.execute(
            "SELECT payload FROM investigation_plans WHERE investigation_id=%s "
            "ORDER BY created_at DESC LIMIT 1",
            (investigation_id,),
        ).fetchone()
        patch = connection.execute(
            "SELECT payload FROM investigation_patches WHERE investigation_id=%s "
            "ORDER BY created_at DESC LIMIT 1",
            (investigation_id,),
        ).fetchone()
        validation = connection.execute(
            "SELECT payload FROM investigation_validations WHERE investigation_id=%s "
            "ORDER BY created_at DESC LIMIT 1",
            (investigation_id,),
        ).fetchone()
        approval = connection.execute(
            "SELECT decision,valid,artifact_kind FROM investigation_approvals "
            "WHERE investigation_id=%s ORDER BY created_at DESC LIMIT 5",
            (investigation_id,),
        ).fetchall()
        events = traces.for_case(settings, investigation_id)
    body = {
        "investigation": traces.public_row(case) if case else None,
        "methodology": [
            "Deterministic npm range comparison",
            "H-MEM recall does not assign exposure",
            "Model output is a proposal",
        ],
        "evidence": evidence,
        "assessments": assessments,
        "plan": plan["payload"] if plan else None,
        "patch": patch["payload"] if patch else None,
        "validation": validation["payload"] if validation else None,
        "approvals": approval,
        "agent_events": events,
        "uncertainties": [
            "Deployment execution was not proven in the demo path.",
            "Syft/Trivy/OSV-Scanner were not executed.",
        ],
    }
    return body
