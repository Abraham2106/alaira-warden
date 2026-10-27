from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from alaira_warden.correlation.history import evaluate_deployment_history
from alaira_warden.correlation.models import (
    Advisory,
    Component,
    PackageRule,
    Snapshot,
    VersionRange,
)
from alaira_warden.inventory.models import DeploymentRecord

NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)


def history_case():
    application_id = uuid4()
    current = Snapshot(
        id=uuid4(),
        application_id=application_id,
        commit_sha="a" * 40,
        observed_at=NOW,
        completeness="complete",
        components=(Component(id="current", name="lodash", resolved_version="4.17.21"),),
    )
    old = Snapshot(
        id=uuid4(),
        application_id=application_id,
        commit_sha="b" * 40,
        observed_at=NOW - timedelta(days=90),
        completeness="complete",
        components=(Component(id="old", name="lodash", resolved_version="4.17.20"),),
    )
    advisory = Advisory(
        source="fixture",
        source_id="GHSA-35jh-r3h4-6jhm",
        content_hash="c" * 64,
        evidence_status="confirmed",
        affected_complete=True,
        affected=(
            PackageRule(
                ecosystem="npm",
                package_name="lodash",
                ranges=(VersionRange(type="npm", expression="<4.17.21"),),
            ),
        ),
    )
    deployment = DeploymentRecord(
        application_id=application_id,
        environment="production",
        artifact_ref="image@sha256:old",
        snapshot_id=old.id,
        commit_sha=old.commit_sha,
        deployed_at=old.observed_at + timedelta(hours=1),
        retired_at=NOW - timedelta(days=10),
        source_reference="release-ticket:historic",
    )
    return current, old, advisory, deployment


def test_safe_current_version_keeps_retired_vulnerable_deployment_open():
    current, old, advisory, deployment = history_case()
    result = evaluate_deployment_history(current, advisory, [deployment], [old], now=NOW)
    assert result.current.exposure == "not_affected"
    assert result.follow_up == "required"
    previous = result.deployments[0]
    assert previous.state == "retired"
    assert previous.assessment.historical
    assert previous.assessment.exposure == "potential"
    assert previous.execution == previous.compromise == "unknown"
    assert result.provenance_verified is False
    assert "current_safe_snapshot_does_not_close_deployment_history" in result.reasons
    # A second assessment of safe HEAD does not mutate or remove the prior result.
    evaluate_deployment_history(current, advisory, [], [], now=NOW)
    assert previous.assessment.findings[0].version_affected is True


def test_commit_only_resolves_to_exact_snapshot_and_active_deployment_is_separate():
    current, old, advisory, deployment = history_case()
    deployment = deployment.model_copy(update={"snapshot_id": None, "retired_at": None})
    result = evaluate_deployment_history(current, advisory, [deployment], [old], now=NOW)
    assert result.deployments[0].state == "active"
    assert result.deployments[0].assessment.snapshot_id == old.id
    assert result.follow_up == "required"


def test_missing_ambiguous_and_future_deployments_never_mean_safe():
    current, old, advisory, deployment = history_case()
    for snapshots, changed in (
        ([], deployment),
        (
            [old, old.model_copy(update={"id": uuid4()})],
            deployment.model_copy(update={"snapshot_id": None}),
        ),
        (
            [old],
            deployment.model_copy(
                update={"deployed_at": NOW + timedelta(days=1), "retired_at": None}
            ),
        ),
    ):
        result = evaluate_deployment_history(
            current,
            advisory,
            [changed],
            snapshots,
            history_complete=True,
            now=NOW,
        )
        assert result.follow_up == "review_required"
        assert result.deployments[0].state == "unresolved"
        assert result.deployments[0].assessment is None


def test_preliminary_advisory_retains_matching_history_without_confirming_exposure():
    current, old, advisory, deployment = history_case()
    result = evaluate_deployment_history(
        current,
        advisory.model_copy(update={"evidence_status": "preliminary"}),
        [deployment],
        [old],
        now=NOW,
    )
    assert result.follow_up == "required"
    assert result.deployments[0].assessment.exposure == "undetermined"


def test_complete_safe_history_is_required_before_negative_conclusion():
    current, old, advisory, deployment = history_case()
    safe_old = old.model_copy(update={"components": current.components})
    partial = evaluate_deployment_history(current, advisory, [deployment], [safe_old], now=NOW)
    complete = evaluate_deployment_history(
        current,
        advisory,
        [deployment],
        [safe_old],
        history_complete=True,
        now=NOW,
    )
    assert partial.follow_up == "review_required"
    assert complete.follow_up == "not_required"
    assert complete.deployments[0].assessment.exposure == "not_affected"


def test_cross_application_and_commit_mismatch_fail_closed():
    current, old, advisory, deployment = history_case()
    with pytest.raises(ValueError, match="another application"):
        evaluate_deployment_history(
            current,
            advisory,
            [deployment.model_copy(update={"application_id": uuid4()})],
            [old],
            now=NOW,
        )
    with pytest.raises(ValueError, match="does not match"):
        evaluate_deployment_history(
            current,
            advisory,
            [deployment.model_copy(update={"commit_sha": "d" * 40})],
            [old],
            now=NOW,
        )
