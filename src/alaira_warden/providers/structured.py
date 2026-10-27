"""Investigation JSON that a model may propose. It cannot assign exposure or call tools."""

from __future__ import annotations

import json
import re

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from alaira_warden.providers.errors import ProviderError

_URL = re.compile(r"https?://[^\s\"'<>]+")
_EXPOSURE = re.compile(
    r"(?i)\b("
    r"confirmed exposure|definite exposure|definitely exposed|exposure confirmed|"
    r"confirmed vulnerable|definitely vulnerable|"
    r"afectaci[oó]n confirmada|exposici[oó]n confirmada|explotaci[oó]n confirmada"
    r")\b"
)
_FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL)


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str = Field(min_length=1, max_length=80)
    url: str | None = None


class _Fact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[str] = Field(max_length=20)


class _Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement: str = Field(min_length=1, max_length=2000)
    assumptions: list[str] = Field(max_length=20)


class _Proposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement: str = Field(min_length=1, max_length=2000)


class InvestigationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    facts: list[_Fact] = Field(max_length=20)
    hypotheses: list[_Hypothesis] = Field(max_length=20)
    references: list[str] = Field(max_length=20)
    limitations: list[str] = Field(max_length=20)
    proposals: list[_Proposal] = Field(max_length=20)


def _fail(reason: str) -> None:
    raise ProviderError(provider="providers", kind="invalid_output", reason=reason)


def _json_text(text: str) -> str:
    stripped = text.strip()
    fenced = _FENCE.fullmatch(stripped)
    if fenced:
        stripped = fenced.group(1).strip()
    return stripped


def _scan(value: object, allowed_urls: set[str]) -> None:
    if isinstance(value, str):
        if _EXPOSURE.search(value):
            _fail("the model cannot assign definitive exposure")
        for match in _URL.findall(value):
            candidate = match.rstrip(".,);]")
            if candidate not in allowed_urls:
                _fail("a reference URL is not in the provided evidence")
        return
    if isinstance(value, list):
        for item in value:
            _scan(item, allowed_urls)
        return
    if isinstance(value, dict):
        for item in value.values():
            _scan(item, allowed_urls)


def validate_investigation(text: str, evidence: list[EvidenceRecord]) -> dict:
    raw_text = _json_text(text)
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError:
        _fail("structured output is not the expected JSON object")
    if not isinstance(payload, dict):
        _fail("structured output is not the expected JSON object")
    if "exposure" in payload or "tool_calls" in payload or "tools" in payload:
        if "exposure" in payload:
            _fail("the model cannot assign exposure")
        _fail("the model cannot invoke tools")
    try:
        parsed = InvestigationOutput.model_validate(payload)
    except ValidationError:
        _fail("structured output does not match the investigation contract")

    known_ids = {item.id for item in evidence}
    allowed_urls = {item.url for item in evidence if item.url}
    for fact in parsed.facts:
        unknown = [item for item in fact.evidence_ids if item not in known_ids]
        if unknown:
            _fail("a fact cites evidence that was not provided")
    for reference in parsed.references:
        if reference not in known_ids and reference not in allowed_urls:
            _fail("a reference is not in the provided evidence")
    dumped = parsed.model_dump()
    _scan(dumped, allowed_urls)
    return dumped
