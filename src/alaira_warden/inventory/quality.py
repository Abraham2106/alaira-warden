"""Completeness and configurable expiry. Expiry does not rewrite history."""

from datetime import datetime, timedelta

from alaira_warden.inventory.errors import InventoryError
from alaira_warden.inventory.models import (
    Completeness,
    InventoryAssessment,
    InventorySnapshot,
    InventoryWarning,
    require_utc,
)

QUALITY_POLICY = "inventory-quality-1"
_HARD_FAILURES = frozenset(
    {
        "missing_lockfile",
        "invalid_lockfile",
        "unsupported_lockfile",
        "invalid_manifest",
    }
)


def classify_completeness(
    *,
    components_present: bool,
    warnings: list[InventoryWarning],
    syft_requested: bool,
    syft_ok: bool,
) -> Completeness:
    codes = {warning.code for warning in warnings}
    blocking = any(warning.blocks_completeness for warning in warnings)
    unresolved_sources = bool(codes & _HARD_FAILURES) and not components_present
    if syft_requested and not syft_ok and not components_present:
        return "failed"
    if unresolved_sources or (not components_present and blocking):
        return "failed"
    if not components_present:
        return "failed"
    if blocking or (syft_requested and not syft_ok):
        return "partial"
    return "complete"


def assess_snapshot(
    snapshot: InventorySnapshot, *, now: datetime, max_age: timedelta
) -> InventoryAssessment:
    if max_age.total_seconds() <= 0:
        raise InventoryError("configuration", "Inventory max age must be positive")
    observed = require_utc(snapshot.observed_at)
    current = require_utc(now)
    expired = current - observed >= max_age
    warnings = list(snapshot.warnings)
    if expired:
        warnings.append(
            InventoryWarning(
                code="inventory_expired",
                message="Inventory is older than the configured maximum age",
                blocks_completeness=True,
            )
        )
    limits_conclusion = snapshot.completeness != "complete" or expired
    return InventoryAssessment(
        completeness=snapshot.completeness,
        expired=expired,
        limits_conclusion=limits_conclusion,
        warnings=warnings,
        max_age_seconds=int(max_age.total_seconds()),
    )


def retain_snapshots(
    history: list[InventorySnapshot], snapshot: InventorySnapshot
) -> list[InventorySnapshot]:
    """Append a new observation. Earlier snapshots stay in place."""
    return [*history, snapshot]
