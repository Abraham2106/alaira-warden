import hashlib
import io
import os
import stat
import tarfile
from pathlib import Path, PurePosixPath

from alaira_warden.execution.models import Artifact, Limits

FORBIDDEN = {".git", ".venv", ".ssh", ".npmrc", ".pypirc", "node_modules"}
WINDOWS_DEVICES = {"con", "prn", "aux", "nul"} | {
    f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10)
}


class ArchiveRejected(ValueError):
    """A file tree or artifact violates the execution policy."""


def is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)
    )


def safe_parts(name: str) -> tuple[str, ...]:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or "\\" in name or ":" in name or "\x00" in name:
        raise ArchiveRejected("Unsafe archive path.")
    for part in path.parts:
        if part in {"..", "."} or part.endswith((" ", ".")):
            raise ArchiveRejected("Unsafe archive path component.")
        if part.split(".")[0].lower() in WINDOWS_DEVICES:
            raise ArchiveRejected("Reserved archive path component.")
    return path.parts


def pack_input(source: Path, allowed_root: Path, limits: Limits) -> bytes:
    root = allowed_root.resolve(strict=True)
    source = source.absolute()
    if not source.is_relative_to(root):
        raise ArchiveRejected("Input must be under the approved root.")
    current = root
    for part in source.relative_to(root).parts:
        if part in {".", ".."}:
            raise ArchiveRejected("Input path must be canonical.")
        current /= part
        if is_link(current.lstat()):
            raise ArchiveRejected("Input links and reparse points are not allowed.")
    if not source.is_dir():
        raise ArchiveRejected("Input must be a prepared directory.")
    stream = io.BytesIO()
    total = count = 0
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for directory, directories, files in os.walk(source, followlinks=False):
            for name in sorted(directories + files):
                path = Path(directory) / name
                parts = safe_parts(path.relative_to(source).as_posix())
                if any(
                    part in FORBIDDEN or part == ".env" or part.startswith(".env.")
                    for part in parts
                ):
                    raise ArchiveRejected("Prepare an input snapshot without secrets or caches.")
                info = path.lstat()
                if is_link(info) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                    raise ArchiveRejected("Only regular input files and directories are allowed.")
                count += 1
                if count > limits.files:
                    raise ArchiveRejected("Input file count exceeds policy.")
                if stat.S_ISDIR(info.st_mode):
                    continue
                total += info.st_size
                if total > limits.input_bytes:
                    raise ArchiveRejected("Input bytes exceed policy.")
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                with os.fdopen(os.open(path, flags), "rb") as file:
                    actual = os.fstat(file.fileno())
                    if not stat.S_ISREG(actual.st_mode) or (
                        actual.st_ino != info.st_ino or actual.st_size != info.st_size
                    ):
                        raise ArchiveRejected("Input changed while preparing the snapshot.")
                    entry = tarfile.TarInfo("/".join(parts))
                    entry.size, entry.uid, entry.gid = actual.st_size, 10001, 10001
                    entry.mode = 0o755 if info.st_mode & 0o111 else 0o644
                    archive.addfile(entry, file)
    return stream.getvalue()


def unpack_artifacts(data: bytes, target: Path, limits: Limits) -> tuple[Artifact, ...]:
    artifacts = []
    total = count = 0
    target.mkdir(parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r|") as archive:
        for entry in archive:
            count += 1
            if count > limits.files:
                raise ArchiveRejected("Artifact count exceeds policy.")
            parts = safe_parts(entry.name)
            if not parts or parts[0] != "artifacts":
                raise ArchiveRejected("Artifact archive must have its expected root.")
            if entry.isdir():
                continue
            if not entry.isfile() or len(parts) < 2:
                raise ArchiveRejected("Artifact links and special files are not allowed.")
            total += entry.size
            if entry.size < 0 or total > limits.artifact_bytes:
                raise ArchiveRejected("Artifact size exceeds policy.")
            destination = target.joinpath(*parts[1:])
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(entry)
            if source is None:
                raise ArchiveRejected("Artifact content is missing.")
            content = source.read(entry.size + 1)
            if len(content) != entry.size:
                raise ArchiveRejected("Artifact content has an unexpected size.")
            with destination.open("xb") as file:
                file.write(content)
            artifacts.append(
                Artifact(
                    path="/".join(parts[1:]),
                    size=entry.size,
                    sha256=hashlib.sha256(content).hexdigest(),
                )
            )
    return tuple(artifacts)
