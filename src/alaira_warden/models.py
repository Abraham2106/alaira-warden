import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class ApplicationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=120)
    repository: str = Field(min_length=3, max_length=201)

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
    status: Literal["detected", "requires_intervention"]
    exposure: Literal["undetermined"]
    created_at: datetime
