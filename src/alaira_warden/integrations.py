"""Integration inventory. Configuration is never advertised as a verified connection."""

from dataclasses import dataclass

from alaira_warden.config import Settings


@dataclass(frozen=True)
class AdapterSpec:
    id: str
    name: str
    kind: str
    scope: str
    secret_env: str | None
    url_env: str | None = None
    notes: str = ""


ADAPTERS: tuple[AdapterSpec, ...] = (
    AdapterSpec(
        "github",
        "GitHub Security",
        "source",
        "mvp",
        "WARDEN_GITHUB_TOKEN",
        notes="Public global advisories allow unauthenticated reads; private repository "
        "operations require scoped authorization. Implementation is pending.",
    ),
    AdapterSpec(
        "osv",
        "OSV",
        "source",
        "mvp",
        None,
        notes="Public data source; no API key. Adapter implementation is pending.",
    ),
    AdapterSpec(
        "nvd",
        "NVD",
        "source",
        "mvp",
        "WARDEN_NVD_API_KEY",
        notes="API key is optional for rate limits. Absence is not treated as verification.",
    ),
    AdapterSpec(
        "cisa-kev",
        "CISA KEV",
        "source",
        "mvp",
        None,
        notes="Public catalog; no API key. Adapter implementation is pending.",
    ),
    AdapterSpec(
        "syft",
        "Syft",
        "inventory",
        "mvp",
        None,
        notes="Local tool. Runs only after an isolated checkout adapter exists.",
    ),
    AdapterSpec(
        "trivy",
        "Trivy",
        "scanner",
        "mvp",
        None,
        notes="Local tool. A missing scan is a failure, not an approval.",
    ),
    AdapterSpec(
        "osv-scanner",
        "OSV-Scanner",
        "scanner",
        "mvp",
        None,
        notes="Local tool. Results must be stored separately from Trivy.",
    ),
    AdapterSpec(
        "meterless",
        "Meterless",
        "model-access",
        "hackathon",
        "WARDEN_METERLESS_API_KEY",
        "WARDEN_METERLESS_BASE_URL",
        notes="Hackathon requirement. Endpoint and contract are unset until verified.",
    ),
    AdapterSpec(
        "nvidia",
        "NVIDIA",
        "model",
        "candidate",
        "WARDEN_NVIDIA_API_KEY",
        "WARDEN_NVIDIA_BASE_URL",
        notes="Candidate model. Model output is not evidence of exposure.",
    ),
    AdapterSpec(
        "grok",
        "Grok / X",
        "research",
        "conditional",
        "WARDEN_GROK_API_KEY",
        notes="Conditional. Publications remain unverified until corroborated.",
    ),
    AdapterSpec(
        "zetaris",
        "Zetaris",
        "data",
        "conditional",
        "WARDEN_ZETARIS_API_KEY",
        notes="Conditional. No query runs until access and schema are confirmed.",
    ),
    AdapterSpec(
        "cursor",
        "Cursor programático",
        "engineering",
        "conditional",
        "WARDEN_CURSOR_API_KEY",
        notes="Conditional product automation. Local Cursor use is not this adapter.",
    ),
)


def catalog() -> tuple[AdapterSpec, ...]:
    return ADAPTERS


def secret_present(settings: Settings, item: AdapterSpec) -> bool:
    if not item.secret_env:
        return False
    value = getattr(settings, item.secret_env.lower())
    return bool(value.get_secret_value())


def url_present(settings: Settings, item: AdapterSpec) -> bool:
    if not item.url_env:
        return False
    return bool(getattr(settings, item.url_env.lower()).strip())


def integration_status(settings: Settings, checks=()) -> list[dict]:
    rows = []
    latest = {row["adapter"]: row["payload"] for row in checks}
    connected = {"github", "osv", "nvd", "cisa-kev", "meterless", "zetaris"}
    for item in ADAPTERS:
        configured = secret_present(settings, item) or url_present(settings, item)
        if item.secret_env is None and item.url_env is None:
            auth = {"mode": "none", "configured": False}
        else:
            auth = {
                "mode": "env",
                "secret_env": item.secret_env,
                "url_env": item.url_env,
                "configured": configured,
            }
        rows.append(
            {
                "id": item.id,
                "name": item.name,
                "kind": item.kind,
                "scope": item.scope,
                "status": latest.get(item.id, {}).get(
                    "status",
                    "implemented_unverified" if item.id in connected else "not_implemented",
                ),
                "verified": latest.get(item.id, {}).get("verified", False) is True,
                "verified_operation": latest.get(item.id, {}).get("operation"),
                "last_checked_at": latest.get(item.id, {}).get("checked_at"),
                "engine_verified": False if item.id == "meterless" else None,
                "auth": auth,
                "notes": "Client connected; verification applies only to the recorded operation. "
                "Sponsor acceptance remains pending."
                if item.id in connected
                else item.notes,
            }
        )
    return rows
