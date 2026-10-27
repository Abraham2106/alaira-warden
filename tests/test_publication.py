"""Real Git artifact identity, controlled GitHub transport; no PR is sent."""

import copy
import json
from uuid import uuid4

import pytest

from alaira_warden.identity import Principal
from alaira_warden.intelligence.http import HttpResponse
from alaira_warden.publication import GitHubPublisher, approve, assert_approved
from alaira_warden.remediation import remediate
from tests.test_remediation_pipeline import ControlledRunner, prepared  # noqa: F401


def person(app, role="administrador", active=True):
    return Principal(
        subject_id=uuid4(),
        is_active=active,
        authentication_method="api_credential",
        assignments=[{"role": role, "application_id": app}],
    )


@pytest.fixture
def publication(prepared):  # noqa: F811
    request, policy = prepared
    artifact = remediate(
        request,
        ControlledRunner(policy),
        authorized_repositories={request.application_id: request.repository},
    )
    principal = person(request.application_id)
    approval = approve(
        artifact,
        "owner/repo",
        "main",
        principal=principal,
        justification="Reviewed exact commit and scanner outputs.",
    )
    return request, artifact, principal, approval


@pytest.mark.parametrize(
    "field,value", [("proposed_sha", "a" * 40), ("diff", "changed"), ("validated", False)]
)
def test_artifact_change_invalidates_approval(publication, field, value):
    _, artifact, principal, approval = publication
    artifact = {**artifact, field: value}
    with pytest.raises((PermissionError, ValueError)):
        assert_approved(
            approval, artifact, "owner/repo", "main", approver=principal, publisher=principal
        )


def test_destination_revocation_and_scope_are_rechecked(publication):
    request, artifact, principal, approval = publication
    with pytest.raises(PermissionError):
        assert_approved(
            approval, artifact, "owner/repo", "release", approver=principal, publisher=principal
        )
    with pytest.raises(PermissionError):
        assert_approved(
            approval,
            artifact,
            "owner/repo",
            "main",
            approver=principal.model_copy(update={"is_active": False}),
            publisher=principal,
        )
    with pytest.raises(PermissionError):
        approve(
            artifact,
            "owner/repo",
            "main",
            principal=person(uuid4()),
            justification="Scope mismatch must deny this.",
        )
    with pytest.raises(PermissionError):
        approve(
            artifact,
            "owner/repo",
            "main",
            principal=person(request.application_id, "auditor"),
            justification="Auditor cannot approve this.",
        )


class GitHub:
    def __init__(self, artifact):
        self.artifact, self.pulls, self.requests = artifact, [], []
        self.head = False
        self.lose_response = False
        self.base_sha = artifact["base_sha"]

    def upload(self, *_args, **_kwargs):
        self.head = True

    def send(self, request):
        self.requests.append(request)
        if request.method == "POST":
            assert request.url == "https://api.github.com/repos/owner/repo/pulls"
            self.pulls = [
                {
                    "number": 12,
                    "html_url": "https://github.com/owner/repo/pull/12",
                    "head": {
                        "sha": self.artifact["proposed_sha"],
                        "ref": self.artifact["branch"],
                        "repo": {"full_name": "owner/repo"},
                    },
                    "base": {
                        "ref": "main",
                        "sha": self.artifact["base_sha"],
                        "repo": {"full_name": "owner/repo"},
                    },
                }
            ]
            if self.lose_response:
                self.lose_response = False
                raise TimeoutError()
            data, status = self.pulls[0], 201
        elif "/pulls?" in request.url:
            data, status = self.pulls, 200
        elif request.url.endswith("heads/main"):
            data, status = {"object": {"sha": self.base_sha}}, 200
        else:
            data = {"object": {"sha": self.artifact["proposed_sha"]}} if self.head else None
            status = 200 if self.head else 404
        return HttpResponse(status, {}, json.dumps(data).encode())


def publish(publication, transport):
    request, artifact, principal, approval = publication
    audit = []
    result = GitHubPublisher("synthetic-test-token", transport).publish(
        artifact,
        approval,
        repository="owner/repo",
        base="main",
        approver=principal,
        publisher=principal,
        local_repository=request.repository,
        authorized_repository=request.repository,
        audit=lambda action, detail: audit.append((action, detail)),
        uploader=transport.upload,
    )
    return result, audit


def test_lost_post_response_and_retry_preserve_one_pr(publication):
    transport = GitHub(publication[1])
    transport.lose_response = True
    result, audit = publish(publication, transport)
    assert result["number"] == 12 and transport.head
    assert audit[-1][0] == "publication.pr_created"
    second, _ = publish(publication, transport)
    assert second["reconciled"] is True
    assert len([r for r in transport.requests if r.method == "POST"]) == 1


def test_moved_destination_blocks_before_push(publication):
    transport = GitHub(publication[1])
    transport.base_sha = "a" * 40
    with pytest.raises(PermissionError, match="Destination changed"):
        publish(publication, transport)
    assert not transport.head
    assert not [r for r in transport.requests if r.method == "POST"]


def test_validation_tampering_and_mock_are_rejected(publication):
    _, artifact, principal, _ = publication
    changed = copy.deepcopy(artifact)
    changed["attempts"][-1]["validations"][0]["commit"] = "a" * 40
    for invalid in (changed, {**artifact, "synthetic": True}):
        with pytest.raises(ValueError):
            approve(
                invalid,
                "owner/repo",
                "main",
                principal=principal,
                justification="Cannot approve an invalid artifact.",
            )
