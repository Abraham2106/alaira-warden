"""Labeled Nightshift stand-in. Never claims a live hotspot."""

from datetime import UTC, datetime

from alaira_warden.providers.contract import ModelResult, ProviderCheck

MOCK_MODEL = "meterless/mock.demo"
_WARNING = "synthetic_mock_not_nightshift"


class MockNightshift:
    """OpenAI-shaped responses for the demo crew. Identified in every payload."""

    def check(self, operation: str = "models") -> ProviderCheck:
        return ProviderCheck(
            provider="meterless",
            checked_at=datetime.now(UTC),
            status="unconfigured",
            operation=f"mock.{operation}",
            capabilities=[MOCK_MODEL, "meterless/auto"],
            reason="Mock runtime for the guided demo; Nightshift was not contacted",
            verified=False,
        )

    def generate_text(self, **kwargs) -> ModelResult:
        model = kwargs.get("model") or MOCK_MODEL
        prompt = str(kwargs.get("prompt") or "")
        if "evaluator" in prompt.lower() or "exposición" in prompt.lower():
            text = (
                "Evaluator: the deterministic exposure must stay unchanged. "
                "Residual uncertainty: KEV empty, deployment unproven."
            )
        else:
            text = (
                "Planner: next read is lockfile integrity and whether lodash 4.17.20 "
                "ran in production. Do not assign exposure."
            )
        return ModelResult(
            provider="meterless",
            model=model if str(model).startswith("meterless/") else MOCK_MODEL,
            text=text,
            warnings=[_WARNING],
        )

    def generate_investigation(self, **kwargs) -> ModelResult:
        model = kwargs.get("model") or MOCK_MODEL
        structured = {
            "facts": [
                {"statement": "lodash 4.17.20 is in the pinned snapshot", "evidence_ids": []}
            ],
            "hypotheses": [
                {"statement": "Production execution is unknown", "assumptions": ["no deploy proof"]}
            ],
            "references": [],
            "limitations": ["This proposal came from the labeled mock, not Nightshift."],
            "proposals": [{"statement": "Upgrade lodash to 4.17.21 after human review."}],
        }
        return ModelResult(
            provider="meterless",
            model=model if str(model).startswith("meterless/") else MOCK_MODEL,
            text="Review the lockfile and treat this as a mock proposal.",
            structured_output=structured,
            warnings=[_WARNING],
        )
