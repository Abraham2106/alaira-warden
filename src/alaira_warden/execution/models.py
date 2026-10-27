import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Literal
from uuid import UUID


@dataclass(frozen=True)
class Limits:
    timeout_seconds: float = 30
    memory_mb: int = 128
    cpus: float = 1
    pids: int = 64
    workspace_mb: int = 32
    temporary_mb: int = 8
    input_bytes: int = 8 * 1024 * 1024
    output_bytes: int = 256 * 1024
    artifact_bytes: int = 4 * 1024 * 1024
    files: int = 256

    def __post_init__(self):
        bounds = {
            "timeout_seconds": (0.1, 1800),
            "memory_mb": (32, 2048),
            "cpus": (0.1, 4),
            "pids": (8, 256),
            "workspace_mb": (4, 512),
            "temporary_mb": (1, 64),
            "input_bytes": (1, 64 * 1024 * 1024),
            "output_bytes": (64, 4 * 1024 * 1024),
            "artifact_bytes": (1, 32 * 1024 * 1024),
            "files": (1, 2048),
        }
        for name, (minimum, maximum) in bounds.items():
            value = getattr(self, name)
            if not minimum <= value <= maximum:
                raise ValueError(f"Invalid execution limit: {name}")
        if self.input_bytes > self.workspace_mb * 1024 * 1024:
            raise ValueError("Input exceeds the bounded workspace.")


@dataclass(frozen=True)
class Tool:
    image_id: str
    executable: str
    prefix: tuple[str, ...] = ()

    def __post_init__(self):
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", self.image_id):
            raise ValueError("An approved immutable local image ID is required.")
        if not self.executable.startswith("/") or "\x00" in self.executable:
            raise ValueError("Tool executable must be an absolute container path.")


@dataclass(frozen=True)
class ExecutionPolicy:
    input_root: Path
    artifact_root: Path
    allowed_applications: frozenset[UUID]
    tools: Mapping[str, Tool]
    limits: Limits = field(default_factory=Limits)
    docker_host: str = field(
        default_factory=lambda: (
            "npipe:////./pipe/dockerDesktopLinuxEngine"
            if sys.platform == "win32"
            else "unix:///var/run/docker.sock"
        )
    )

    def __post_init__(self):
        # Only a trusted host process constructs policy. User/model requests cannot override it.
        if not self.docker_host.startswith(("unix:///", "npipe:////./pipe/")):
            raise ValueError("The executor only permits a local Docker daemon.")
        if not self.input_root.is_absolute() or not self.artifact_root.is_absolute():
            raise ValueError("Policy roots must be absolute.")
        source = self.input_root.resolve()
        destination = self.artifact_root.resolve()
        if source.is_relative_to(destination) or destination.is_relative_to(source):
            raise ValueError("Input and artifact roots must not overlap.")
        object.__setattr__(self, "tools", MappingProxyType(dict(self.tools)))


@dataclass(frozen=True)
class Job:
    application_id: UUID
    subject_id: str
    source: Path
    tool: str
    arguments: tuple[str, ...] = ()


@dataclass(frozen=True)
class Artifact:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class JobResult:
    job_id: str
    application_id: UUID
    subject_id: str
    status: Literal[
        "passed",
        "failed",
        "timed_out",
        "cancelled",
        "output_limit",
        "artifact_limit",
        "infrastructure_error",
        "rejected",
    ]
    exit_code: int | None
    output: str
    output_truncated: bool
    artifacts: tuple[Artifact, ...]
    duration_seconds: float
    cleanup_succeeded: bool
    image_id: str
    reason: str | None = None
