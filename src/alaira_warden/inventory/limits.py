"""Explicit budgets for reads, materialization and dependency walks."""

from pydantic import BaseModel, ConfigDict, Field


class InventoryLimits(BaseModel):
    """Finite limits. Callers pass them; nothing here reads the environment."""

    model_config = ConfigDict(extra="forbid")

    max_files: int = Field(default=100, ge=1, le=10_000)
    max_file_bytes: int = Field(default=5_000_000, ge=1)
    max_total_bytes: int = Field(default=20_000_000, ge=1)
    max_response_bytes: int = Field(default=20_000_000, ge=1)
    max_tree_entries: int = Field(default=20_000, ge=1)
    timeout_seconds: float = Field(default=30.0, gt=0, le=600)
    max_dependency_depth: int = Field(default=25, ge=1, le=100)
    max_paths_per_component: int = Field(default=20, ge=1, le=200)
    max_components: int = Field(default=5_000, ge=1)
