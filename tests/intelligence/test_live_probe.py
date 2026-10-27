"""Optional public probe. The default suite does not run this module's test."""

from __future__ import annotations

import os

import pytest

from alaira_warden.intelligence import WorkBudget, query_osv

pytestmark = pytest.mark.skipif(
    os.environ.get("WARDEN_INTELLIGENCE_PROBE") != "1",
    reason="Set WARDEN_INTELLIGENCE_PROBE=1 to query the public OSV API.",
)


def test_public_osv_lodash_probe():
    batch = query_osv(
        package_name="lodash",
        ecosystem="npm",
        version="4.17.20",
        budget=WorkBudget(max_requests=2, timeout_seconds=20, deadline_seconds=30),
    )
    assert batch.source == "osv"
    assert batch.records
    assert all(record.affected for record in batch.records)
