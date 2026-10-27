"""Trusted server records: never accept an approval object from a public caller."""

import hashlib
import json
import re
from datetime import UTC, datetime
from uuid import UUID, uuid4

from alaira_warden.identity import Principal, audit_actor, authorize


def _json_identity(value):
    if isinstance(value, UUID):
        return str(value)
    raise TypeError("Artifact contains an unsupported value")


def _permit(principal: Principal, action: str, application_id: str):
    if not authorize(principal, action, UUID(str(application_id))).allowed:
        raise PermissionError("Publication action denied")


def binding(artifact: dict, repository: str, base: str) -> str:
    """Bind every validation result as well as the exact commit and destination."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid repository")
    if any(p in {".", ".."} for p in repository.split("/")):
        raise ValueError("Invalid repository")
    if (
        not re.fullmatch(r"[A-Za-z0-9_./-]+", base)
        or ".." in base
        or "//" in base
        or base.startswith(("/", "-"))
        or base.endswith(("/", ".", ".lock"))
    ):
        raise ValueError("Invalid destination branch")
    if artifact.get("validated") is not True or artifact.get("status") != "passed":
        raise ValueError("Artifact is not validated")
    if artifact.get("synthetic") is not False or artifact.get("missing_tools"):
        raise ValueError("Synthetic or incomplete validation cannot be approved")
    UUID(str(artifact["application_id"]))
    for name in ("base_sha", "proposed_sha"):
        if not re.fullmatch(r"[a-f0-9]{40}", artifact.get(name, "")):
            raise ValueError("Invalid commit identity")
    for name in ("diff_sha256", "snapshot_sha256"):
        if not re.fullmatch(r"[a-f0-9]{64}", artifact.get(name, "")):
            raise ValueError("Invalid artifact identity")
    if hashlib.sha256(artifact.get("diff", "").encode()).hexdigest() != artifact["diff_sha256"]:
        raise ValueError("Diff changed")
    if not re.fullmatch(r"warden/[a-zA-Z0-9-]+", artifact.get("branch", "")):
        raise ValueError("Invalid publication branch")
    files = artifact.get("files", [])
    if {item["path"] for item in files} != {"package.json", "package-lock.json"}:
        raise ValueError("Unexpected changed files")
    attempts = artifact.get("attempts") or []
    latest = attempts[-1] if attempts else {}
    validations = latest.get("validations") or []
    tools = {item.get("tool") for item in validations}
    if tools != {"project_tests", "syft", "trivy", "osv_scanner"}:
        raise ValueError("Required validations are missing")
    for item in validations:
        if (
            item.get("status") != "passed"
            or item.get("cleanup_succeeded") is not True
            or item.get("commit") != artifact["proposed_sha"]
            or item.get("snapshot_sha256") != artifact["snapshot_sha256"]
            or (item["tool"] != "project_tests" and not item.get("artifacts"))
        ):
            raise ValueError("Validation does not cover this artifact")
    value = {"artifact": artifact, "repository": repository, "base": base}
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=_json_identity).encode()
    ).hexdigest()


def approve(
    artifact: dict, repository: str, base: str, *, principal: Principal, justification: str
) -> dict:
    _permit(principal, "approval.decide", artifact["application_id"])
    if not 10 <= len(justification.strip()) <= 2000:
        raise ValueError("Written justification is required")
    return {
        "id": str(uuid4()),
        "application_id": str(artifact["application_id"]),
        "artifact_id": str(artifact["id"]),
        "binding": binding(artifact, repository, base),
        "repository": repository,
        "base": base,
        "actor": audit_actor(principal),
        "subject_id": str(principal.subject_id),
        "decision": "approved",
        "valid": True,
        "justification": justification.strip(),
        "created_at": datetime.now(UTC).isoformat(),
    }


def assert_approved(
    approval: dict,
    artifact: dict,
    repository: str,
    base: str,
    *,
    approver: Principal,
    publisher: Principal,
):
    """Both principals must be freshly loaded from the identity store at dispatch."""
    _permit(approver, "approval.decide", artifact["application_id"])
    _permit(publisher, "pull_request.publish", artifact["application_id"])
    if (
        approval.get("valid") is not True
        or approval.get("decision") != "approved"
        or approval.get("subject_id") != str(approver.subject_id)
        or approval.get("artifact_id") != str(artifact["id"])
        or approval.get("application_id") != str(artifact["application_id"])
        or approval.get("binding") != binding(artifact, repository, base)
    ):
        raise PermissionError("Approval is stale or invalid")
