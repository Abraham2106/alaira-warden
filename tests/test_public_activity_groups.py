import json
from uuid import uuid4

from alaira_warden.agents import traces
from alaira_warden.config import Settings


def test_public_group_keys_join_runs_without_disclosing_internal_ids(monkeypatch):
    case_id, run_id, other_run = uuid4(), uuid4(), uuid4()
    common = {
        "agent": "scout",
        "stage": "sources",
        "status": "started",
        "summary": "Reading.",
        "created_at": "2026-10-27T16:00:00Z",
        "detail": {"synthetic": True},
        "investigation_id": str(case_id),
    }
    rows = [
        {**common, "run_id": str(run_id)},
        {**common, "run_id": str(run_id)},
        {**common, "run_id": str(other_run)},
        {**common, "run_id": None},
    ]
    monkeypatch.setattr(traces, "recent", lambda *args, **kwargs: rows)
    settings = Settings(_env_file=None)
    result = traces.public_recent(settings)
    assert result[0]["activity_group"] == result[1]["activity_group"]
    assert result[0]["activity_group"] != result[2]["activity_group"]
    assert result[3]["activity_group_kind"] == "case"
    assert result[0]["activity_group_kind"] == "run"
    serialized = json.dumps(result)
    for identifier in (case_id, run_id, other_run):
        assert str(identifier) not in serialized
    assert "detail" not in result[0]
    assert "investigation_id" not in result[0]
    rows.append({**common, "run_id": str(run_id), "detail": {}, "summary": "Private case"})
    assert "Private case" not in json.dumps(traces.public_recent(settings))
