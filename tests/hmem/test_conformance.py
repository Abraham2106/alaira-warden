from alaira_warden.hmem import HMEM, parse_strict_json_array, scorecard
from alaira_warden.hmem.conformance import run_vectors


def test_official_vectors_pass():
    card = scorecard()
    failed = [item for item in card["results"] if item["status"] != "PASS"]
    assert card["verified"], failed
    assert card["total"] == len(run_vectors())


def test_source_is_mandatory():
    engine = HMEM({"clock": lambda: 1})
    try:
        engine.add({"content": "no source", "source": ""})
    except ValueError as error:
        assert "source" in str(error)
    else:
        raise AssertionError("expected rejection")


def test_parse_strict_json_array_strips_fences():
    assert parse_strict_json_array('```json\n["remember this fact"]\n```') == ["remember this fact"]
    assert parse_strict_json_array("not json") == []


def test_query_reinjects_without_deleting_superseded():
    engine = HMEM({"clock": lambda: 1})
    kept = engine.add(
        {
            "content": "we deploy the api with docker on mondays",
            "confidence": 0.9,
            "layer": "long_term",
            "source": "test",
        }
    )
    old = engine.add(
        {
            "content": "we deploy the api with docker on fridays",
            "confidence": 0.9,
            "layer": "long_term",
            "source": "test",
        }
    )
    old.supersededBy = kept.id
    result = engine.query("when do we deploy the api with docker", {"threshold": 0, "topN": 10})
    ids = [item.memory.id for item in result.memories]
    assert ids.index(kept.id) < ids.index(old.id)
    assert engine.store.get(old.id) is not None
    assert "[MEMORY CONTEXT]" in result.context
