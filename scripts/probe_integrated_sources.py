"""Read-only public probes through the actual integrated clients, without credentials."""

import json
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

from alaira_warden.intelligence import (
    SourceError,
    WorkBudget,
    fetch_github_advisory,
    fetch_kev_catalog,
    fetch_nvd_cve,
    query_osv,
)

if __name__ == "__main__":
    calls = {
        "github": lambda budget: fetch_github_advisory("GHSA-35jh-r3h4-6jhm", budget=budget),
        "osv": lambda budget: query_osv(
            package_name="lodash", ecosystem="npm", version="4.17.20", budget=budget
        ),
        "nvd": lambda budget: fetch_nvd_cve("CVE-2020-8203", include_changes=False, budget=budget),
        "cisa-kev": lambda budget: fetch_kev_catalog(budget=budget),
    }
    results = []
    for source, call in calls.items():
        started = monotonic()
        try:
            batch = call(
                WorkBudget(max_requests=2, max_retries=0, timeout_seconds=12, deadline_seconds=25)
            )
            result = {
                "source": source,
                "success": True,
                "records": len(batch.records),
                "complete": batch.complete,
                "warnings": batch.warnings,
            }
        except SourceError as error:
            result = {"source": source, "success": False, "category": error.category}
        result["duration_seconds"] = round(monotonic() - started, 3)
        results.append(result)
    report = {
        "checked_at": datetime.now(UTC).isoformat(),
        "authenticated": False,
        "sponsor_acceptance": False,
        "results": results,
    }
    destination = Path("artifacts/integration/public-clients.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
