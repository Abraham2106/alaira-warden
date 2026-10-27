import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class ApplicationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=120)
    repository: str = Field(min_length=3, max_length=201)
    owner: str | None = Field(default=None, max_length=200)
    organization: str | None = Field(default=None, max_length=200)
    criticality: Literal["low", "medium", "high", "critical"] | None = None
    environments: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("environments")
    @classmethod
    def validate_environments(cls, value):
        if len(set(value)) != len(value) or any(
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", item) for item in value
        ):
            raise ValueError("Use unique environment names with letters, numbers, dots or hyphens.")
        return value

    @field_validator("repository")
    @classmethod
    def validate_repository(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", value):
            raise ValueError("Use GitHub owner/repository, not a URL or local path.")
        if value.split("/")[1] in {".", ".."}:
            raise ValueError("Invalid repository name.")
        return value


class Application(ApplicationCreate):
    id: UUID
    ecosystem: Literal["npm"]
    created_at: datetime


class InvestigationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    application_id: UUID
    title: str = Field(min_length=1, max_length=200)
    source_url: HttpUrl
    description: str = Field(min_length=1, max_length=10000)


class Investigation(InvestigationCreate):
    id: UUID
    status: Literal[
        "detected",
        "requires_intervention",
        "investigating",
        "awaiting_review",
        "closed",
        "cancelled",
    ]
    exposure: Literal["undetermined", "not_affected", "potential", "confirmed"]
    created_at: datetime
