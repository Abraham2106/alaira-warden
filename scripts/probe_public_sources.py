"""Bounded feasibility probes against public sources; no credentials or private data."""

import json
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PROBES = (
    (
        "osv",
        "https://api.osv.dev/v1/query",
        {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.20"},
    ),
    ("github", "https://api.github.com/advisories?ecosystem=npm&per_page=1", None),
    ("nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-23337", None),
    (
        "cisa-kev",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        None,
    ),
)


def probe(name: str, url: str, payload: dict | None) -> dict:
    started = monotonic()
    result = {"source": name, "url": url, "authenticated": False}
    request = Request(
        url,
        data=json.dumps(payload).encode() if payload else None,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "alaira-warden-feasibility/0.1",
        },
    )
    try:
        with urlopen(request, timeout=12) as response:
            raw = response.read(5_000_001)
            if len(raw) > 5_000_000:
                raise ValueError("Response exceeded the probe size limit")
            data = json.loads(raw)
            result.update(http_status=response.status, json_received=True)
            if name == "osv":
                result["records"] = len(data.get("vulns", []))
                result["contract_valid"] = isinstance(data.get("vulns"), list)
            elif name == "github":
                result["records"] = len(data) if isinstance(data, list) else 0
                result["contract_valid"] = (
                    bool(data) and isinstance(data, list) and "ghsa_id" in data[0]
                )
            elif name == "nvd":
                result["records"] = data.get("totalResults", 0)
                result["contract_valid"] = isinstance(data.get("vulnerabilities"), list)
            else:
                result["records"] = len(data.get("vulnerabilities", []))
                result["contract_valid"] = isinstance(data.get("vulnerabilities"), list)
    except HTTPError as error:
        result.update(http_status=error.code, contract_valid=False)
    except (URLError, TimeoutError, ValueError) as error:
        result.update(error_type=type(error).__name__, contract_valid=False)
    result["duration_seconds"] = round(monotonic() - started, 3)
    return result


if __name__ == "__main__":
    report = {
        "checked_at": datetime.now(UTC).isoformat(),
        "scope": "Public synthetic package query; availability is not full integration acceptance.",
        "results": [probe(*parameters) for parameters in PROBES],
    }
    directory = Path(__file__).resolve().parents[1] / "artifacts" / "feasibility"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "public-sources.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
