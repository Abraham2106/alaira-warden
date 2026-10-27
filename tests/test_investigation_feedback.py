"""No live sponsor calls: bounded feedback, durable boundaries, scoped recall."""

import json
from copy import deepcopy
from types import SimpleNamespace

import pytest

from alaira_warden.hmem import HMEM, InvestigationMemory
from alaira_warden.integration.critique import run_planner_evaluator
from alaira_warden.nightshift import deployment_verified
from alaira_warden.providers.contract import ModelResult
from alaira_warden.providers.errors import ProviderError

SETTINGS = SimpleNamespace(
    warden_model_dispatch_policy="allow_minimized", warden_meterless_model="meterless/auto"
)
PLAN = {"steps": ["Read deployment provenance"], "uncertainties": ["Execution unknown"]}
ACCEPT = {"decision": "accept", "feedback": "Read plan preserves uncertainty."}
REVISE = {"decision": "revise", "feedback": "Also read historical deployments."}


class Scripted:
    def __init__(self, *outputs):
        self.outputs = list(outputs)
        self.calls = []

    def generate_text(self, **kwargs):
        self.calls.append(kwargs)
        item = self.outputs.pop(0)
        if isinstance(item, Exception):
            raise item
        return ModelResult(provider="meterless", model="nvidia/nemotron", text=json.dumps(item))


def test_evaluator_revises_and_planner_receives_feedback():
    client = Scripted(PLAN, REVISE, {**PLAN, "steps": ["Read historical deployments"]}, ACCEPT)
    states = []
    result = run_planner_evaluator(
        SETTINGS,
        assessment_ids=["assessment-1"],
        client=client,
        checkpoint=states.append,
        context={"source": "warden_pg.warden_inventory_data", "missing": "deployment"},
    )
    assert result["status"] == "ready"
    assert result["changed_exposure"] is False
    assert result["calls_used"] == 4
    assert result["reserved_seconds"] == 60
    assert "Also read historical deployments" in client.calls[2]["prompt"]
    assert [item["role"] for item in result["iterations"]] == [
        "planner",
        "evaluator",
        "planner",
        "evaluator",
    ]
    assert result["planner"]["steps"] == ["Read historical deployments"]
    assert all(item["timeout"] <= 15 for item in client.calls)
    assert len([state for state in states if state["in_flight"]]) == 4


def test_repeated_revision_exhausts_budget():
    client = Scripted(PLAN, REVISE, PLAN, REVISE)
    result = run_planner_evaluator(SETTINGS, assessment_ids=["a"], client=client)
    assert result["status"] == "requires_intervention"
    assert result["reason"] == "call_budget_exhausted"
    assert result["changed_exposure"] is False


def test_interrupted_reserved_call_is_not_replayed():
    client = Scripted(PLAN)
    states = []

    def checkpoint(state):
        states.append(state)
        if state["in_flight"]:
            raise RuntimeError("simulated process interruption after durable reservation")

    with pytest.raises(RuntimeError):
        run_planner_evaluator(SETTINGS, assessment_ids=["a"], client=client, checkpoint=checkpoint)
    assert not client.calls
    result = run_planner_evaluator(SETTINGS, assessment_ids=["a"], client=client, state=states[-1])
    assert result["reason"] == "interrupted_provider_call"
    assert result["calls_used"] == 1
    assert not client.calls


def test_resume_after_saved_plan_does_not_repeat_planner():
    client = Scripted(PLAN, ACCEPT)
    saved = []

    def checkpoint(state):
        saved.append(deepcopy(state))
        if not state["in_flight"] and state["phase"] == "evaluator":
            raise RuntimeError("simulated stop after committed planner")

    with pytest.raises(RuntimeError):
        run_planner_evaluator(SETTINGS, assessment_ids=["a"], client=client, checkpoint=checkpoint)
    result = run_planner_evaluator(SETTINGS, assessment_ids=["a"], client=client, state=saved[-1])
    assert result["status"] == "ready"
    assert len(client.calls) == 2
    assert result["calls_used"] == 2
    with pytest.raises(ValueError, match="different inputs"):
        run_planner_evaluator(SETTINGS, assessment_ids=["another"], client=client, state=result)


def test_malformed_model_output_does_not_approve():
    client = Scripted({"steps": ["read"], "exposure": "not_affected"})
    result = run_planner_evaluator(SETTINGS, assessment_ids=["a"], client=client)
    assert result["reason"] == "invalid_output"
    assert result["changed_exposure"] is False
    assert result["planner"] is None


def test_provider_failure_retains_reserved_budget_and_reason_only():
    client = Scripted(ProviderError(provider="meterless", kind="offline", reason="private body"))
    result = run_planner_evaluator(SETTINGS, assessment_ids=["a"], client=client)
    assert result["reason"] == "offline"
    assert "private body" not in json.dumps(result)
    assert result["calls_used"] == 1
    assert result["reserved_seconds"] == 15


def test_cancel_and_deadline_prevent_dispatch():
    client = Scripted()
    result = run_planner_evaluator(
        SETTINGS, assessment_ids=["a"], client=client, cancelled=lambda: True
    )
    assert result["status"] == "cancelled"
    result = run_planner_evaluator(SETTINGS, assessment_ids=["a"], client=client, deadline=0)
    assert result["reason"] == "deadline_exceeded"
    assert not client.calls


def test_dispatch_policy_cannot_be_bypassed_by_injected_client():
    denied = SimpleNamespace(warden_model_dispatch_policy="deny", warden_meterless_model="auto")
    client = Scripted()
    result = run_planner_evaluator(denied, assessment_ids=["a"], client=client)
    assert result["reason"] == "dispatch_denied"
    assert not client.calls


def test_scoped_recall_excludes_other_applications_and_unscoped_memory():
    memory = InvestigationMemory(HMEM())
    for case in ("allowed", "other", None):
        memory.remember(
            {
                "content": "lodash advisory historical deployment",
                "confidence": 0.8,
                "source": f"case:{case}",
                "chatId": case,
            }
        )
    result = memory.recall_for_cases("lodash advisory", ["allowed"], {"threshold": 0})
    assert [item["source"] for item in result["memories"]] == ["case:allowed"]
    empty = memory.recall_for_cases("lodash", [], {"threshold": 0})
    assert empty["memories"] == []
    assert empty["context"] == ""


def test_mock_can_never_verify_live_nightshift():
    mock = ModelResult(
        provider="meterless",
        model="meterless/auto",
        text="demo",
        warnings=["synthetic_mock_not_nightshift"],
    )
    assert deployment_verified(mock, "meterless/auto") is False
