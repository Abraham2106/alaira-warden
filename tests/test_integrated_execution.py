"""Product HTTP wiring with real Git objects and deterministic external transports."""

import hashlib
import json
import os
import shutil
from dataclasses import replace
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from alaira_warden.integration.product_actions import ProductActions
from alaira_warden.publication import assert_approved
from tests.test_product_integration import setup_case
from tests.test_remediation_pipeline import ControlledRunner, git, prepared  # noqa: F401


def test_http_remediation_approval_publication_and_idempotence(product, prepared, monkeypatch):  # noqa: F811
    app_id, case_id, _ = setup_case(product)
    request, policy = prepared
    docker = os.getenv("WARDEN_RUN_PRODUCT_DOCKER") == "1"
    version = "4.18.1" if docker else "4.17.21"
    if docker:
        manifest_path = request.repository / "package.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["scripts"] = {"test": "node test.js"}
        manifest_path.write_text(json.dumps(manifest))
        (request.repository / "test.js").write_text(
            "require('node:assert/strict').equal(require('lodash/package.json').version,'4.18.1');"
        )
        git(request.repository, "add", ".")
        git(request.repository, "commit", "-m", "Real API scanner validation")
        request = replace(request, base_sha=git(request.repository, "rev-parse", "HEAD"))
    app_uuid, case_uuid, snapshot_id = UUID(app_id), UUID(case_id), uuid4()
    root = request.repository.parent / "registered"
    root.mkdir()
    shutil.copytree(request.repository, root / app_id)
    configuration = product["settings"].model_copy(
        update={
            "warden_repository_root": str(root),
            "warden_execution_root": str(root.parent / "execution"),
            "warden_remediation_image": os.getenv("WARDEN_REMEDIATION_IMAGE", ""),
        }
    )
    product["settings"].warden_repository_root = str(root)
    service = ProductActions(
        configuration,
        runner_factory=(lambda app: ProductActions(configuration).runner(app))
        if docker
        else (lambda app: ControlledRunner(replace(policy, allowed_applications=frozenset({app})))),
    )
    monkeypatch.setattr(service, "repository", lambda application, sha: root / app_id)
    calls = []

    class Publisher:
        def __init__(self, token):
            pass

        def publish(self, artifact, approval, **kwargs):
            assert_approved(
                approval,
                artifact,
                kwargs["repository"],
                kwargs["base"],
                approver=kwargs["approver"],
                publisher=kwargs["publisher"],
            )
            calls.append(artifact["proposed_sha"])
            return {
                "number": 42,
                "url": "https://github.com/test-owner/test-repository/pull/42",
                "reconciled": len(calls) > 1,
            }

    service.publisher_factory = Publisher
    monkeypatch.setattr("alaira_warden.integration.routes.ProductActions", lambda settings: service)
    with product["connect"](product["settings"]) as connection:
        connection.execute(
            "INSERT INTO inventory_snapshots(id,application_id,commit_ref,tool_name,"
            "tool_version,completeness) "
            "VALUES (%s,%s,%s,'lockfile','fixture','complete')",
            (snapshot_id, app_uuid, request.base_sha),
        )
        plan = {"action": "update_dependency", "packages": ["lodash@4.17.20"]}
        connection.execute(
            "INSERT INTO investigation_plans(id,investigation_id,actor,payload,content_hash) "
            "VALUES (%s,%s,'test',%s,%s)",
            (
                uuid4(),
                case_uuid,
                Jsonb(plan),
                hashlib.sha256(json.dumps(plan).encode()).hexdigest(),
            ),
        )
    client, headers = product["client"], product["headers"]
    path = f"/api/investigations/{case_id}/remediation"
    body = {
        "snapshot_id": str(snapshot_id),
        "request_key": str(uuid4()),
        "package": "lodash",
        "versions": [version],
        "max_attempts": 1,
    }
    outsider, _ = product["issue"]("auditor", None)
    assert client.post(path, headers=outsider, json=body).status_code == 403
    response = client.post(path, headers=headers, json=body)
    assert response.status_code == 200, response.text
    job = response.json()
    assert job["status"] == "passed", job
    assert job["payload"]["synthetic"] is False
    repeated = client.post(path, headers=headers, json=body)
    assert repeated.json()["id"] == job["id"]
    job_path = path + "/" + job["id"]
    assert client.post(job_path + "/publish", headers=headers).status_code == 409
    approval = client.post(
        job_path + "/approve",
        headers=headers,
        json={"base": "main", "justification": "Reviewed exact commit and tests."},
    )
    assert approval.status_code == 200, approval.text
    published = client.post(job_path + "/publish", headers=headers)
    assert published.status_code == 200, published.text
    assert published.json()["number"] == 42
    context = client.get(f"/api/investigations/{case_id}/context", headers=headers).json()
    assert context["remediations"][0]["payload"]["validated"] is True
    assert context["validations"][0]["payload"]["commit"] == job["payload"]["proposed_sha"]
    assert context["publications"][0]["payload"]["number"] == 42
    report = client.get(f"/api/investigations/{case_id}/report", headers=headers).json()
    assert report["remediations"] and report["publications"]
    assert calls == [job["payload"]["proposed_sha"]]


def test_closed_case_cannot_restart_or_advance(product):
    client, headers = product["client"], product["headers"]
    app_id, case_id, _ = setup_case(product)
    from tests.test_product_integration import GHSA

    snapshot = client.post(
        f"/api/applications/{app_id}/inventory/refresh", headers=headers, json={}
    ).json()
    run = client.post(
        f"/api/investigations/{case_id}/runs",
        headers=headers,
        json={
            "snapshot_id": snapshot["id"],
            "advisory_identifier": GHSA,
            "request_key": str(uuid4()),
        },
    ).json()
    response = client.post(
        f"/api/investigations/{case_id}/close",
        headers=headers,
        json={"outcome": "discarded", "justification": "Discard controlled test case."},
    )
    assert response.status_code == 201
    assert (
        client.post(
            f"/api/investigations/{case_id}/runs/{run['id']}/advance", headers=headers
        ).status_code
        == 409
    )


def test_history_is_read_evaluated_and_reported_by_the_product(product):
    from datetime import UTC, datetime, timedelta

    from tests.test_product_integration import GHSA

    client, headers = product["client"], product["headers"]
    app_id, case_id, _ = setup_case(product)
    old = client.post(
        f"/api/applications/{app_id}/inventory/refresh", headers=headers, json={}
    ).json()
    deployed = client.post(
        f"/api/applications/{app_id}/deployments",
        headers=headers,
        json={
            "schema_version": 1,
            "deployments": [
                {
                    "application_id": app_id,
                    "snapshot_id": old["id"],
                    "environment": "production",
                    "artifact_ref": "controlled:old",
                    "source_reference": "test:deploy",
                    "deployed_at": (datetime.now(UTC) - timedelta(days=2)).isoformat(),
                    "retired_at": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
                }
            ],
        },
    )
    assert deployed.status_code == 201, deployed.text
    current_id = uuid4()
    with product["connect"](product["settings"]) as connection:
        connection.execute(
            "INSERT INTO inventory_snapshots(id,application_id,commit_ref,tool_name,"
            "tool_version,completeness) "
            "VALUES (%s,%s,%s,'lockfile','fixture','complete')",
            (current_id, UUID(app_id), "b" * 40),
        )
        connection.execute(
            "INSERT INTO components(id,snapshot_id,name,ecosystem,resolved_version,"
            "direct,dependency_paths) "
            "VALUES (%s,%s,'lodash','npm','4.17.21',true,%s)",
            (uuid4(), current_id, Jsonb([["lodash@4.17.21"]])),
        )
    run = client.post(
        f"/api/investigations/{case_id}/runs",
        headers=headers,
        json={
            "snapshot_id": str(current_id),
            "advisory_identifier": GHSA,
            "request_key": str(uuid4()),
        },
    ).json()
    for _ in range(3):
        response = client.post(
            f"/api/investigations/{case_id}/runs/{run['id']}/advance", headers=headers
        )
        assert response.status_code == 200, response.text
    context = client.get(f"/api/investigations/{case_id}/context", headers=headers).json()
    assert context["histories"]
    assert any(row["payload"]["follow_up"] == "required" for row in context["histories"])
    assert any(row["payload"]["historical"] for row in context["assessments"])
    report = client.get(f"/api/investigations/{case_id}/report", headers=headers).json()
    assert report["historical_exposure"]
    closed = client.post(
        f"/api/investigations/{case_id}/close",
        headers=headers,
        json={"outcome": "not_affected", "justification": "Current version alone is insufficient."},
    )
    assert closed.status_code == 409


def test_publication_and_new_correction_share_case_lock(product):
    import pytest

    app_id, case_id, _ = setup_case(product)
    service = ProductActions(product["settings"])
    with service.case_lock(case_id):
        with pytest.raises(ValueError, match="Another correction"):
            with service.case_lock(case_id):
                pass
