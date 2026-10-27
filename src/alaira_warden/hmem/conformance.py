"""Execute the official H-MEM vectors against this Python port."""

from __future__ import annotations

import json
from pathlib import Path

from alaira_warden.hmem.engine import HMEM

VENDOR_VECTORS = (
    Path(__file__).resolve().parents[3]
    / "vendor"
    / "meterless-hmem"
    / "conformance"
    / "vectors"
    / "vectors.json"
)
DAY_MS = 24 * 60 * 60 * 1000


def load_vectors(path: Path | None = None) -> dict:
    return json.loads((path or VENDOR_VECTORS).read_text(encoding="utf-8"))


def _approx(left: float, right: float, eps: float = 1e-9) -> bool:
    return abs(left - right) < eps


def run_vectors(path: Path | None = None) -> list[dict]:
    vectors = load_vectors(path)
    t0 = vectors["clock"]
    results: list[dict] = []

    def record(section: str, case_id: str, description: str, fn) -> None:
        try:
            fn()
            results.append(
                {"id": case_id, "section": section, "description": description, "status": "PASS"}
            )
        except Exception as error:
            results.append(
                {
                    "id": case_id,
                    "section": section,
                    "description": description,
                    "status": "FAIL",
                    "detail": str(error),
                }
            )

    def assert_true(cond: bool, message: str) -> None:
        if not cond:
            raise AssertionError(message)

    for case in vectors["sections"]["record-validation"]:

        def body(case=case):
            hmem = HMEM({"clock": lambda: t0})
            rejected = False
            try:
                hmem.add({"content": case["input"]["content"], "source": case["input"]["source"]})
            except Exception:
                rejected = True
            assert_true(
                rejected == (case["expect"] == "reject"),
                f"expected {case['expect']}, got {'reject' if rejected else 'accept'}",
            )

        record("record-validation", case["id"], case["description"], body)

    for case in vectors["sections"]["feedback-deltas"]:

        def body(case=case):
            hmem = HMEM({"clock": lambda: t0})
            memory = hmem.add(
                {
                    "content": "feedback target record",
                    "confidence": case["start"],
                    "source": "conformance",
                }
            )
            before = memory.accessCount
            hmem.feedback(memory.id, case["kind"])
            after = hmem.store.get(memory.id)
            assert_true(
                _approx(after.confidence, case["expectConfidence"]),
                f"confidence {after.confidence}, expected {case['expectConfidence']}",
            )
            if "expectAccessDelta" in case:
                assert_true(
                    after.accessCount - before == case["expectAccessDelta"],
                    (
                        f"accessCount delta {after.accessCount - before}, "
                        f"expected {case['expectAccessDelta']}"
                    ),
                )
            if case.get("expectTag"):
                assert_true(case["expectTag"] in after.tags, f"missing tag {case['expectTag']}")

        record("feedback-deltas", case["id"], case["description"], body)

    for case in vectors["sections"]["ranking-order"]:

        def body(case=case):
            hmem = HMEM({"clock": lambda: t0})
            by_key = {}
            for item in case["records"]:
                by_key[item["key"]] = hmem.add(
                    {
                        "content": item["content"],
                        "confidence": item["confidence"],
                        "layer": item["layer"],
                        "source": "conformance",
                    }
                )
            for item in case["records"]:
                if item.get("supersededByKey"):
                    by_key[item["key"]].supersededBy = by_key[item["supersededByKey"]].id
            result = hmem.query(case["query"], {"threshold": 0, "topN": 10})
            order = [item.memory.id for item in result.memories]
            expected = [by_key[key].id for key in case["expectOrder"]]
            for index in range(len(expected) - 1):
                assert_true(
                    order.index(expected[index]) < order.index(expected[index + 1]),
                    (
                        f"expected {case['expectOrder'][index]} before "
                        f"{case['expectOrder'][index + 1]}, got {order}"
                    ),
                )

        record("ranking-order", case["id"], case["description"], body)

    for case in vectors["sections"]["sleep-guardrails"]:

        def body(case=case):
            now = t0
            hmem = HMEM({"clock": lambda: now})
            by_key = {}
            for item in case["records"]:
                by_key[item["key"]] = hmem.add(
                    {
                        "content": item["content"],
                        "source": item["source"],
                        "derivedFrom": item.get("derivedFrom"),
                    }
                )
            now = t0 + case["ageDays"] * DAY_MS
            before = json.dumps(sorted(item.id for item in hmem.store.all()))
            preview = hmem.sleep.preview()
            assert_true(
                json.dumps(sorted(item.id for item in hmem.store.all())) == before,
                "preview mutated the store",
            )
            for key in case["expectArchived"]:
                assert_true(by_key[key].id in preview.toArchive, f"{key} should be archivable")
            for key in case["expectProtected"]:
                assert_true(
                    by_key[key].id not in preview.toArchive,
                    f"{key} is guardrail-protected and must not archive",
                )
            report = hmem.sleep.execute(preview)
            for key in case["expectProtected"]:
                assert_true(
                    hmem.store.get(by_key[key].id) is not None,
                    f"{key} was deleted despite guardrails",
                )
            assert_true(
                isinstance(report.backupId, str) and len(report.backupId) > 0,
                "execute must return a backupId",
            )

        record("sleep-guardrails", case["id"], case["description"], body)

    for case in vectors["sections"]["conflict-gate"]:

        def body(case=case):
            hmem = HMEM({"clock": lambda: t0})
            left = hmem.add(
                {
                    "content": case["a"]["content"],
                    "confidence": case["a"]["confidence"],
                    "source": "conformance",
                }
            )
            right = hmem.add(
                {
                    "content": case["b"]["content"],
                    "confidence": case["b"]["confidence"],
                    "source": "conformance",
                }
            )
            found = hmem.conflicts.scan()
            assert_true(
                len(found) > 0,
                "opposing always/never pair on similar content must be detected",
            )
            outcome = hmem.conflicts.auto_resolve(found[0])
            assert_true(
                outcome in {"resolved", "queued"},
                f"outcome must be resolved or queued, got {outcome}",
            )
            if outcome == "resolved":
                loser = next(
                    (
                        item
                        for item in (hmem.store.get(left.id), hmem.store.get(right.id))
                        if item and item.supersededBy
                    ),
                    None,
                )
                assert_true(
                    loser is not None, "resolved conflicts must mark the loser supersededBy"
                )
            assert_true(
                hmem.store.get(left.id) is not None and hmem.store.get(right.id) is not None,
                "conflict resolution must never delete records",
            )

        record("conflict-gate", case["id"], case["description"], body)

    for case in vectors["sections"]["ledger-audit"]:

        def body(case=case):
            hmem = HMEM({"clock": lambda: t0})
            memory = hmem.add(
                {"content": "audited record", "confidence": case["start"], "source": "conformance"}
            )
            hmem.feedback(memory.id, case["kind"])
            history = hmem.ledger.history(memory.id)
            actions = [item.action for item in history]
            assert_true(
                actions == case["expectActions"],
                f"actions {actions}, expected {case['expectActions']}",
            )
            feedback = history[-1]
            assert_true(
                _approx(feedback.previousState["confidence"], case["expectPrev"]),
                f"previousState.confidence {feedback.previousState['confidence']}, "
                f"expected {case['expectPrev']}",
            )
            assert_true(
                _approx(feedback.newState["confidence"], case["expectNew"]),
                (
                    f"newState.confidence {feedback.newState['confidence']}, "
                    f"expected {case['expectNew']}"
                ),
            )

        record("ledger-audit", case["id"], case["description"], body)

    for case in vectors["sections"]["dream-boundary"]:

        def body(case=case):
            hmem = HMEM({"clock": lambda: t0})
            for item in case["records"]:
                hmem.add(
                    {"content": item["content"], "type": item["type"], "source": "conformance"}
                )
            count_before = len(hmem.store.all())
            proposals = hmem.dreaming.dream()
            assert_true(
                len(proposals) > 0,
                "two related preferences must produce at least one proposal",
            )
            assert_true(
                len(hmem.store.all()) == count_before,
                "dreaming must not materialize anything before approval",
            )
            created = hmem.dreaming.approve(proposals[0].id)
            if created:
                assert_true(
                    created.layer == "long_term", "approved proposals materialize as long_term"
                )
                assert_true(
                    len(created.derivedFrom or []) > 0,
                    "approved proposals carry derivedFrom lineage",
                )

        record("dream-boundary", case["id"], case["description"], body)

    return results


def scorecard(results: list[dict] | None = None) -> dict:
    rows = results if results is not None else run_vectors()
    passed = sum(1 for item in rows if item["status"] == "PASS")
    return {
        "engine": "hmem",
        "passed": passed,
        "total": len(rows),
        "verified": passed == len(rows) and len(rows) > 0,
        "results": rows,
    }
