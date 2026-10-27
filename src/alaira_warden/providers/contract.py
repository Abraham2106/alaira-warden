"""Shared ProviderCheck / ModelResult v1 types.

Unknown token usage stays ``None``. A zero is recorded only when the provider
sends that number. Model text is a proposal, not technical evidence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ProviderName = Literal["meterless", "nvidia", "zetaris"]
CheckStatus = Literal[
    "unconfigured",
    "unauthorized",
    "forbidden",
    "offline",
    "available",
    "unsupported",
]


class Usage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


class ProviderCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: ProviderName
    checked_at: datetime
    status: CheckStatus
    operation: str = Field(min_length=1, max_length=80)
    capabilities: list[str] = Field(default_factory=list)
    reason: str = Field(max_length=300)
    verified: bool

    def model_post_init(self, _context: object) -> None:
        if self.status == "available" and not self.verified:
            raise ValueError("available requires verified=True")
        if self.status != "available" and self.verified:
            raise ValueError("verified=True is only valid when status is available")


class ModelResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["meterless", "nvidia"]
    model: str = Field(min_length=1, max_length=120)
    request_id: str | None = None
    text: str = Field(min_length=1)
    structured_output: dict | None = None
    usage: Usage | None = None
    warnings: list[str] = Field(default_factory=list)


class ZetarisQueryResult(BaseModel):
    """Tabular read with provenance. This is not a Warden finding and writes nothing."""

    model_config = ConfigDict(extra="forbid")

    provider: Literal["zetaris"] = "zetaris"
    queried_at: datetime
    columns: list[str]
    rows: list[list[str | int | float | bool | None]]
    sources: list[str]
    request_id: str
    statement: str
    operation: Literal["sql.read"] = "sql.read"
    warnings: list[str] = Field(default_factory=list)
