"""Read one repository-scoped Dependabot alert; never mutate GitHub alerts."""

import re
import time
from datetime import UTC, datetime

from alaira_warden.intelligence.errors import SourceError
from alaira_warden.intelligence.github import normalize_github_advisory
from alaira_warden.intelligence.hashing import content_hash
from alaira_warden.intelligence.http import UrllibTransport, WorkBudget, request_json
from alaira_warden.intelligence.models import Attribution, SourceRecord

DOCS = "https://docs.github.com/en/rest/dependabot/alerts"


def fetch_dependabot_alert(repository: str, number: int, *, token: str, transport=None):
    """Repository comes from the authorized application, never an inbound URL."""
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
        or any(part in {".", ".."} for part in repository.split("/"))
        or isinstance(number, bool)
        or number < 1
    ):
        raise ValueError("Invalid repository or alert number")
    if not token.strip():
        raise SourceError(
            category="configuration",
            source="github",
            operation="dependabot",
            reason="token_required",
        )
    path = f"/repos/{repository}/dependabot/alerts/{number}"
    result = request_json(
        source="github",
        operation="dependabot",
        method="GET",
        url=f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        body=None,
        transport=transport or UrllibTransport(),
        budget=WorkBudget(max_requests=1, max_retries=0, timeout_seconds=15),
        sleeper=time.sleep,
        hosts=frozenset({"api.github.com"}),
        path_allowed=lambda p: p == path,
    )
    payload = result.payload
    if not isinstance(payload, dict) or payload.get("number") != number:
        raise SourceError(
            category="invalid_response",
            source="github",
            operation="dependabot",
            reason="alert_unavailable",
        )
    advisory = payload.get("security_advisory")
    vulnerability = payload.get("security_vulnerability")
    if not isinstance(advisory, dict) or not isinstance(vulnerability, dict):
        raise SourceError(
            category="invalid_response",
            source="github",
            operation="dependabot",
            reason="invalid_alert",
        )
    # Limit the rule to this alert's package, retaining the GHSA/CVE lineage.
    record, _ = normalize_github_advisory(
        {**advisory, "vulnerabilities": [vulnerability]}, retrieved_at=datetime.now(UTC)
    )
    if record is None:
        raise SourceError(
            category="invalid_response",
            source="github",
            operation="dependabot",
            reason="invalid_advisory",
        )
    dependency = payload.get("dependency")
    dependency = dependency if isinstance(dependency, dict) else {}
    origin = {
        "provider": "dependabot",
        "repository": repository,
        "number": number,
        "state": payload.get("state"),
        "updated_at": payload.get("updated_at"),
        "fixed_at": payload.get("fixed_at"),
        "dismissed_at": payload.get("dismissed_at"),
        "manifest_path": dependency.get("manifest_path"),
        "scope": dependency.get("scope"),
        "relationship": dependency.get("relationship"),
        "advisory": record.origin,
    }
    return SourceRecord.model_validate(
        {
            **record.model_dump(),
            "source_id": f"dependabot:{repository}:{number}",
            "aliases": [record.source_id, *record.aliases],
            "source_url": f"https://github.com/{repository}/security/dependabot/{number}",
            "origin": origin,
            "content_hash": content_hash(origin),
            # Repository alert status does not establish safety of other versions/deployments.
            "affected_complete": False,
            "warnings": [
                *record.warnings,
                "dependabot_is_not_independent_corroboration",
                "alert_state_is_not_deployment_evidence",
            ],
            "attribution": Attribution(
                provider="GitHub Dependabot",
                documentation_url=DOCS,
                notes="Repository-scoped alert; shares GitHub Advisory lineage.",
            ),
        }
    )
