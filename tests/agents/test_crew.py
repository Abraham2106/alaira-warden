from uuid import uuid4

import pytest

from alaira_warden.agents.mocks import MockNightshift
from alaira_warden.agents.response import compose_plan
from alaira_warden.agents.roster import public_roster
from alaira_warden.agents.traces import emit
from tests.test_product_integration import GHSA, setup_case


def test_public_roster_has_distinct_responsibilities():
    crew = public_roster()
    assert {item["id"] for item in crew} >= {
        "warden",
        "scout",
        "arbiter",
        "mnemonic",
        "planner",
        "evaluator",
        "guardian",
    }
    assert all(item["never"] for item in crew)
    assert any("fusiona" in item["never"].lower() for item in crew)


def test_unknown_agent_and_status_are_rejected():
    with pytest.raises(KeyError):
        emit(
            None,
            investigation_id=uuid4(),
            agent="nobody",
            stage="x",
            status="started",
            summary="x",
        )
    with pytest.raises(ValueError, match="Unknown agent event status"):
        emit(
            None,
            investigation_id=uuid4(),
            agent="warden",
            stage="x",
            status="done",
            summary="x",
        )


def test_guided_demo_runs_the_crew_without_sponsor_calls(product):
    client, headers = product["client"], product["headers"]
    response = client.post("/api/demo/run", headers=headers)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["synthetic"] is True
    assert body["credentials_used"] is False
    assert body["sponsors_verified"] is False
    assert body["nightshift_deployment_verified"] is False
    assert body["events"]
    agents = {event["agent"] for event in body["events"]}
    assert {"warden", "cartographer", "scout", "arbiter", "planner"}.issubset(agents)
    timeline = client.get(f"/api/investigations/{body['investigation_id']}/agents", headers=headers)
    assert timeline.status_code == 200
    assert len(timeline.json()) >= len(body["events"])
    report = client.get(f"/api/investigations/{body['investigation_id']}/report", headers=headers)
    assert report.status_code == 200
    payload = report.json()
    assert payload["agent_events"]
    assert payload["plan"]["action"] == "update_dependency"
    merge = client.post(f"/api/investigations/{body['investigation_id']}/merge", headers=headers)
    assert merge.status_code == 403
    activity = client.get("/api/agents/activity", headers=headers)
    assert activity.status_code == 200
    assert activity.json()
    public = client.get("/agents/activity")
    assert public.status_code == 200
    public_events = public.json()["events"]
    assert public_events
    assert all("investigation_id" not in event for event in public_events)


def test_plan_approval_does_not_merge_and_can_close(product):
    client, headers = product["client"], product["headers"]
    app_id, case_id, _ = setup_case(product)
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
    for _ in range(3):
        assert (
            client.post(
                f"/api/investigations/{case_id}/runs/{run['id']}/advance", headers=headers
            ).status_code
            == 200
        )
    plan = client.post(f"/api/investigations/{case_id}/plan", headers=headers)
    assert plan.status_code == 201, plan.text
    assert "compromise_follow_up" in plan.json()["payload"]
    approval = client.post(
        f"/api/investigations/{case_id}/approval",
        headers=headers,
        json={
            "artifact_kind": "plan",
            "decision": "approved",
            "justification": "Human review of the labeled plan artifact.",
        },
    )
    assert approval.status_code == 201, approval.text
    assert approval.json()["valid"] is True
    assert client.post(f"/api/investigations/{case_id}/merge", headers=headers).status_code == 403
    assert client.post(f"/api/investigations/{case_id}/deploy", headers=headers).status_code == 403
    paused = client.post(f"/api/investigations/{case_id}/runs/{run['id']}/pause", headers=headers)
    assert paused.status_code == 200, paused.text
    closed = client.post(
        f"/api/investigations/{case_id}/close",
        headers=headers,
        json={
            "outcome": "discarded",
            "justification": "Demo closure keeps evidence and does not merge.",
        },
    )
    assert closed.status_code == 201, closed.text
    assert client.get(f"/api/investigations/{case_id}", headers=headers).json()["status"] == (
        "closed"
    )


def test_mock_nightshift_is_labeled():
    mock = MockNightshift()
    result = mock.generate_investigation(model="meterless/auto", task="x")
    assert "synthetic_mock_not_nightshift" in result.warnings
    assert result.model == "meterless/auto"
    check = mock.check()
    assert check.verified is False
    assert check.status != "available"


def test_compose_plan_requires_correlation(product):
    _app_id, case_id, _ = setup_case(product)
    with pytest.raises(ValueError, match="Correlate"):
        compose_plan(product["settings"], investigation_id=case_id, actor="tester")
