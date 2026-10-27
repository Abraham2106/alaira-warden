from datetime import UTC, datetime

from alaira_warden.correlation.models import (
    Advisory,
    Assessment,
    Context,
    Finding,
    PriorityPolicy,
    Snapshot,
)
from alaira_warden.correlation.npm_ranges import npm_matches
from alaira_warden.correlation.versions import match_rules


def priority(exposure: str, matched: bool | None, advisory: Advisory, context: Context) -> str:
    if exposure == "not_affected":
        return "none"
    if advisory.known_exploited is True and matched is True:
        return "critical" if context.asset_criticality in {"high", "critical"} else "high"
    score = advisory.severity_score
    if score is None:
        return "unassigned"
    value = (
        "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    )
    if value == "high" and context.asset_criticality == "critical":
        return "critical"
    return value


def evaluate_snapshot(
    snapshot: Snapshot,
    advisory: Advisory,
    context: Context | None = None,
    policy: PriorityPolicy | None = None,
    now: datetime | None = None,
) -> Assessment:
    policy = policy or PriorityPolicy()
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("Evaluation time must include timezone.")
    context = context or Context(application_id=snapshot.application_id, snapshot_id=snapshot.id)
    if context.application_id != snapshot.application_id or context.snapshot_id != snapshot.id:
        raise ValueError("Exposure context must belong to the evaluated application and snapshot.")
    ids = [component.id for component in snapshot.components]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate component IDs in the snapshot.")
    reference_time = context.deployed_at if context.historical and context.deployed_at else now
    age = (reference_time - snapshot.observed_at).total_seconds()
    warnings = []
    fresh = reference_time <= now and 0 <= age <= policy.max_inventory_age_seconds
    if not fresh:
        warnings.append("inventory_stale_or_future_dated")
    if snapshot.completeness != "complete":
        warnings.append("inventory_incomplete")
    if not snapshot.components:
        warnings.append("inventory_has_no_components")
    confirmed_evidence = advisory.evidence_status == "confirmed" and not advisory.withdrawn
    if not confirmed_evidence:
        warnings.append("advisory_not_confirmed_or_withdrawn")
    if not advisory.affected:
        warnings.append("affected_package_identity_unknown")
    if not advisory.affected_complete:
        warnings.append("advisory_affected_scope_incomplete")
    npm_pairs = set()
    for component in snapshot.components:
        if component.ecosystem.casefold() != "npm" or not component.resolved_version:
            continue
        for package in advisory.affected:
            if package.ecosystem.casefold() != "npm" or package.package_name != component.name:
                continue
            for item in package.ranges:
                if item.type == "npm" and item.expression is not None:
                    npm_pairs.add((component.resolved_version, item.expression))
            if len(npm_pairs) > 20000:
                raise ValueError("npm comparison budget exceeded.")
    npm_results = npm_matches(npm_pairs)
    findings = []
    for component in snapshot.components:
        reasons = list(warnings)
        rules = tuple(
            rule
            for rule in advisory.affected
            if rule.ecosystem.casefold() == component.ecosystem.casefold()
            and rule.package_name == component.name
        )
        matched = None
        exposure = "undetermined"
        if component.ecosystem.casefold() != "npm":
            reasons.append("ecosystem_not_supported")
        elif not rules:
            reasons.append(
                "package_identity_not_listed" if advisory.affected else "package_identity_unknown"
            )
            if (
                advisory.affected
                and advisory.affected_complete
                and confirmed_evidence
                and fresh
                and snapshot.completeness == "complete"
            ):
                exposure = "not_affected"
        else:
            result = match_rules(component.resolved_version, rules, npm_results)
            matched = result.affected
            reasons.extend(result.reasons)
            if matched is True and confirmed_evidence:
                exposure = "potential"
                # Deployment and explicit complete conditions require evidence references.
                if (
                    context.deployed is True
                    and context.deployment_reference
                    and context.conditions_complete
                    and fresh
                    and snapshot.completeness == "complete"
                    and all(
                        condition.satisfied is True and condition.evidence_reference
                        for condition in context.conditions
                    )
                ):
                    exposure = "confirmed"
                else:
                    reasons.append("exposure_conditions_or_deployment_not_fully_verified")
            elif (
                matched is False
                and advisory.affected_complete
                and confirmed_evidence
                and fresh
                and snapshot.completeness == "complete"
            ):
                exposure = "not_affected"
            if context.historical:
                reasons.append("historical_deployment_evaluated_separately")
        confidence = (
            "high"
            if exposure in {"confirmed", "not_affected"}
            else (
                "medium"
                if exposure == "potential" and fresh and snapshot.completeness == "complete"
                else "low"
            )
        )
        findings.append(
            Finding(
                component_id=component.id,
                package_name=component.name,
                resolved_version=component.resolved_version,
                dependency_paths=component.dependency_paths,
                version_affected=matched,
                exposure=exposure,
                priority=priority(exposure, matched, advisory, context),
                confidence=confidence,
                reasons=tuple(dict.fromkeys(reasons)),
            )
        )
    statuses = {finding.exposure for finding in findings}
    summary = "undetermined"
    for candidate in ("confirmed", "potential", "undetermined", "not_affected"):
        if candidate in statuses:
            summary = candidate
            break
    return Assessment(
        application_id=snapshot.application_id,
        snapshot_id=snapshot.id,
        commit_sha=snapshot.commit_sha,
        advisory_id=advisory.source_id,
        advisory_revision=advisory.content_hash,
        policy_version=policy.version,
        evaluated_at=now,
        historical=context.historical,
        exposure=summary,
        findings=tuple(findings),
        warnings=tuple(warnings),
    )
