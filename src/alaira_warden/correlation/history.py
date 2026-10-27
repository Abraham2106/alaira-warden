"""Assess deployment observations without letting a safe HEAD erase past exposure."""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Literal

from alaira_warden.correlation.engine import evaluate_snapshot
from alaira_warden.correlation.models import (
    Advisory,
    Assessment,
    Context,
    Contract,
    PriorityPolicy,
    Snapshot,
)
from alaira_warden.inventory.models import DeploymentRecord


class DeploymentAssessment(Contract):
    deployment: DeploymentRecord
    state: Literal["active", "retired", "unresolved"]
    assessment: Assessment | None = None
    reasons: tuple[str, ...] = ()
    execution: Literal["unknown"] = "unknown"
    compromise: Literal["unknown"] = "unknown"


class DeploymentHistory(Contract):
    current: Assessment
    deployments: tuple[DeploymentAssessment, ...]
    follow_up: Literal["required", "review_required", "not_required"]
    reasons: tuple[str, ...]
    deployment_history_complete: bool
    # This evaluator checks imported observations, not authenticity of their source.
    provenance_verified: Literal[False] = False


def evaluate_deployment_history(
    current_snapshot: Snapshot,
    advisory: Advisory,
    deployments: Sequence[DeploymentRecord],
    snapshots: Sequence[Snapshot],
    *,
    history_complete: bool = False,
    asset_criticality: Literal["low", "medium", "high", "critical"] = "medium",
    policy: PriorityPolicy | None = None,
    now: datetime | None = None,
) -> DeploymentHistory:
    """Caller supplies authorized, immutable snapshots and retains this result by revision.

    A commit-only deployment resolves only to a unique supplied snapshot. Missing,
    ambiguous and future-dated observations remain explicit; they never mean safe.
    Imported deployment records do not assert execution or exploitation conditions.
    """
    now = now or datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Evaluation time must include timezone")
    if len(deployments) > 1000 or len(snapshots) > 1000:
        raise ValueError("Deployment history evaluation budget exceeded")
    application_id = current_snapshot.application_id
    by_id = {current_snapshot.id: current_snapshot}
    for snapshot in snapshots:
        if snapshot.application_id != application_id:
            raise ValueError("Historical snapshot belongs to another application")
        if snapshot.id in by_id and snapshot != by_id[snapshot.id]:
            raise ValueError("Snapshot identity has conflicting content")
        by_id[snapshot.id] = snapshot
    by_commit: dict[str, list[Snapshot]] = {}
    for snapshot in by_id.values():
        by_commit.setdefault(snapshot.commit_sha, []).append(snapshot)
    current = evaluate_snapshot(
        current_snapshot,
        advisory,
        Context(
            application_id=application_id,
            snapshot_id=current_snapshot.id,
            asset_criticality=asset_criticality,
        ),
        policy,
        now,
    )
    evaluations = []
    for deployment in deployments:
        if deployment.application_id != application_id:
            raise ValueError("Deployment belongs to another application")
        snapshot = by_id.get(deployment.snapshot_id) if deployment.snapshot_id else None
        reason = None
        if deployment.snapshot_id is None:
            candidates = by_commit.get(deployment.commit_sha or "", [])
            if len(candidates) == 1:
                snapshot = candidates[0]
            else:
                reason = "deployment_snapshot_missing_or_ambiguous"
        elif snapshot is None:
            reason = "deployment_snapshot_missing"
        if snapshot and deployment.commit_sha and deployment.commit_sha != snapshot.commit_sha:
            raise ValueError("Deployment commit does not match its snapshot")
        if deployment.deployed_at > now:
            reason = "deployment_is_future_dated"
        if reason:
            evaluations.append(
                DeploymentAssessment(
                    deployment=deployment,
                    state="unresolved",
                    reasons=(reason,),
                )
            )
            continue
        retired = deployment.retired_at is not None and deployment.retired_at <= now
        assessment = evaluate_snapshot(
            snapshot,
            advisory,
            Context(
                application_id=application_id,
                snapshot_id=snapshot.id,
                deployed=True,
                deployment_reference=deployment.source_reference,
                environment=deployment.environment,
                historical=retired,
                deployed_at=deployment.deployed_at,
                asset_criticality=asset_criticality,
            ),
            policy,
            now,
        )
        evaluations.append(
            DeploymentAssessment(
                deployment=deployment,
                state="retired" if retired else "active",
                assessment=assessment,
                reasons=("deployment_does_not_prove_execution", "compromise_not_established"),
            )
        )
    vulnerable = any(
        item.assessment and any(f.version_affected is True for f in item.assessment.findings)
        for item in evaluations
    )
    uncertain = not history_complete or any(
        item.assessment is None or item.assessment.exposure == "undetermined"
        for item in evaluations
    )
    if vulnerable:
        follow_up, reasons = "required", ("affected_deployment_requires_follow_up",)
        if current.exposure == "not_affected":
            reasons += ("current_safe_snapshot_does_not_close_deployment_history",)
    elif uncertain:
        follow_up, reasons = "review_required", ("deployment_history_incomplete_or_undetermined",)
    else:
        follow_up, reasons = "not_required", ("provided_complete_deployment_history_not_affected",)
    return DeploymentHistory(
        current=current,
        deployments=tuple(evaluations),
        follow_up=follow_up,
        reasons=reasons,
        deployment_history_complete=history_complete,
    )
