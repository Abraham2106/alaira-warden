from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from alaira_warden.correlation.engine import evaluate_snapshot
from alaira_warden.correlation.models import (
    Advisory,
    Component,
    Condition,
    Context,
    PackageRule,
    Snapshot,
    VersionRange,
)

NOW = datetime(2026, 10, 27, 5, 0, tzinfo=UTC)


def inputs():
    snapshot = Snapshot(
        id=uuid4(),
        application_id=uuid4(),
        commit_sha="a" * 40,
        observed_at=NOW,
        completeness="complete",
        components=(
            Component(id="direct", name="fixture", resolved_version="1.2.3"),
            Component(
                id="transitive",
                name="fixture",
                resolved_version="1.2.0",
                dependency_paths=(("application", "parent", "fixture"),),
            ),
        ),
    )
    advisory = Advisory(
        source="fixture",
        source_id="TEST-1",
        content_hash="b" * 64,
        evidence_status="confirmed",
        affected_complete=True,
        severity_score=8,
        affected=(
            PackageRule(
                ecosystem="npm",
                package_name="fixture",
                ranges=(VersionRange(type="npm", expression="<1.2.3"),),
            ),
        ),
    )
    return snapshot, advisory


def test_direct_transitive_and_safe_version_are_distinguished():
    snapshot, advisory = inputs()
    result = evaluate_snapshot(snapshot, advisory, now=NOW)
    safe, vulnerable = result.findings
    assert safe.exposure == "not_affected" and safe.priority == "none"
    assert vulnerable.exposure == "potential" and vulnerable.priority == "high"
    assert vulnerable.dependency_paths == (("application", "parent", "fixture"),)
    assert vulnerable.compromise == "unknown"
    assert result.exposure == "potential"


def test_confirmed_exposure_requires_evidence_for_deployment_and_conditions():
    snapshot, advisory = inputs()
    context = Context(
        application_id=snapshot.application_id,
        snapshot_id=snapshot.id,
        deployed=True,
        deployment_reference="deployment-proof",
        conditions_complete=True,
        conditions=(Condition(name="feature_enabled", satisfied=True),),
    )
    result = evaluate_snapshot(snapshot, advisory, context, now=NOW)
    assert result.exposure == "potential"
    context = context.model_copy(
        update={
            "conditions": (
                Condition(
                    name="feature_enabled", satisfied=True, evidence_reference="configuration-proof"
                ),
            )
        }
    )
    result = evaluate_snapshot(snapshot, advisory, context, now=NOW)
    assert result.exposure == "confirmed"
    assert result.findings[1].compromise == "unknown"


@pytest.mark.parametrize(
    "change",
    [
        {"completeness": "partial"},
        {"observed_at": NOW - timedelta(days=2)},
        {"observed_at": NOW + timedelta(hours=1)},
    ],
)
def test_incomplete_or_stale_inventory_limits_negative_conclusions(change):
    snapshot, advisory = inputs()
    result = evaluate_snapshot(snapshot.model_copy(update=change), advisory, now=NOW)
    assert result.findings[0].exposure == "undetermined"
    assert result.findings[1].exposure == "potential"


def test_historical_case_is_not_closed_by_a_current_safe_snapshot():
    snapshot, advisory = inputs()
    historical = Context(
        application_id=snapshot.application_id,
        snapshot_id=snapshot.id,
        historical=True,
        deployed=True,
        deployment_reference="old-deployment",
    )
    old_result = evaluate_snapshot(snapshot, advisory, historical, now=NOW)
    safe_snapshot = snapshot.model_copy(update={"components": (snapshot.components[0],)})
    current_result = evaluate_snapshot(safe_snapshot, advisory, now=NOW)
    assert old_result.exposure == "potential" and old_result.historical
    assert current_result.exposure == "not_affected"
    assert old_result.findings[1].compromise == "unknown"


def test_historical_snapshot_age_uses_the_evidenced_deployment_time():
    snapshot, advisory = inputs()
    old_time = NOW - timedelta(days=365)
    snapshot = snapshot.model_copy(update={"observed_at": old_time})
    context = Context(
        application_id=snapshot.application_id,
        snapshot_id=snapshot.id,
        historical=True,
        deployed=True,
        deployment_reference="historical-record",
        deployed_at=old_time,
        conditions_complete=True,
    )
    result = evaluate_snapshot(snapshot, advisory, context, now=NOW)
    assert result.exposure == "confirmed"
    assert "inventory_stale_or_future_dated" not in result.warnings


def test_missing_npm_engine_is_unknown_not_safe(monkeypatch):
    snapshot, advisory = inputs()
    monkeypatch.setattr("alaira_warden.correlation.npm_ranges.shutil.which", lambda _: None)
    result = evaluate_snapshot(snapshot, advisory, now=NOW)
    assert result.exposure == "undetermined"
    assert all(finding.version_affected is None for finding in result.findings)


def test_partial_advisory_cannot_rule_out_a_safe_looking_component():
    snapshot, advisory = inputs()
    result = evaluate_snapshot(
        snapshot, advisory.model_copy(update={"affected_complete": False}), now=NOW
    )
    assert result.findings[0].exposure == "undetermined"
    assert result.findings[1].exposure == "potential"


def test_unknown_identity_or_empty_inventory_is_indeterminate():
    snapshot, advisory = inputs()
    assert (
        evaluate_snapshot(snapshot, advisory.model_copy(update={"affected": ()}), now=NOW).exposure
        == "undetermined"
    )
    assert (
        evaluate_snapshot(
            snapshot.model_copy(update={"components": ()}), advisory, now=NOW
        ).exposure
        == "undetermined"
    )


def test_contradictory_evidence_cannot_confirm_or_rule_out_exposure():
    snapshot, advisory = inputs()
    advisory = advisory.model_copy(update={"evidence_status": "contradictory"})
    result = evaluate_snapshot(snapshot, advisory, now=NOW)
    assert {finding.exposure for finding in result.findings} == {"undetermined"}


def test_cross_application_context_is_rejected():
    snapshot, advisory = inputs()
    context = Context(application_id=uuid4(), snapshot_id=snapshot.id)
    with pytest.raises(ValueError):
        evaluate_snapshot(snapshot, advisory, context, now=NOW)


def test_priority_is_repeatable_and_independent_from_confidence():
    snapshot, advisory = inputs()
    advisory = advisory.model_copy(update={"known_exploited": True, "severity_score": None})
    context = Context(
        application_id=snapshot.application_id,
        snapshot_id=snapshot.id,
        asset_criticality="critical",
    )
    one = evaluate_snapshot(snapshot, advisory, context, now=NOW)
    two = evaluate_snapshot(snapshot, advisory, context, now=NOW)
    assert one == two
    assert one.findings[1].priority == "critical"
    assert one.findings[1].confidence == "medium"
