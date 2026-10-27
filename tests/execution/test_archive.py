import io
import tarfile
from dataclasses import replace

import pytest

from alaira_warden.execution.archive import ArchiveRejected, pack_input, unpack_artifacts
from alaira_warden.execution.models import Limits


def archive_entry(name, content=b"ok", entry_type=tarfile.REGTYPE):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        entry = tarfile.TarInfo(name)
        entry.type = entry_type
        entry.size = len(content) if entry_type == tarfile.REGTYPE else 0
        entry.linkname = "/etc/passwd" if entry_type == tarfile.SYMTYPE else ""
        archive.addfile(entry, io.BytesIO(content))
    return stream.getvalue()


def test_input_cannot_escape_approved_root(tmp_path):
    root = tmp_path / "approved"
    root.mkdir()
    with pytest.raises(ArchiveRejected):
        pack_input(tmp_path, root, Limits())


@pytest.mark.parametrize("name", [".env", ".env.local", ".npmrc", ".git", ".ssh"])
def test_input_cannot_include_secrets_or_host_configuration(tmp_path, name):
    (tmp_path / name).write_text("sensitive", encoding="utf-8")
    with pytest.raises(ArchiveRejected):
        pack_input(tmp_path, tmp_path, Limits())


def test_input_limits_and_unprivileged_ownership(tmp_path):
    (tmp_path / "source.js").write_text("content", encoding="utf-8")
    with pytest.raises(ArchiveRejected):
        pack_input(tmp_path, tmp_path, replace(Limits(), input_bytes=3))
    data = pack_input(tmp_path, tmp_path, Limits())
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        entry = archive.getmember("source.js")
        assert entry.uid == entry.gid == 10001
        assert entry.isreg()


@pytest.mark.parametrize(
    "name",
    [
        "artifacts/../../escaped",
        "/escaped",
        "other/file",
        "artifacts/file:stream",
        "artifacts/CON",
        "artifacts/a\\b",
        "artifacts/name.",
    ],
)
def test_artifact_paths_cannot_escape_or_use_windows_devices(tmp_path, name):
    with pytest.raises(ArchiveRejected):
        unpack_artifacts(archive_entry(name), tmp_path / "result", Limits())
    assert not (tmp_path / "escaped").exists()


@pytest.mark.parametrize("entry_type", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_artifact_links_and_special_files_are_rejected(tmp_path, entry_type):
    with pytest.raises(ArchiveRejected):
        unpack_artifacts(
            archive_entry("artifacts/link", entry_type=entry_type), tmp_path / "result", Limits()
        )


def test_artifact_limit_and_hash(tmp_path):
    data = archive_entry("artifacts/result.txt", b"proof")
    with pytest.raises(ArchiveRejected):
        unpack_artifacts(data, tmp_path / "too-small", replace(Limits(), artifact_bytes=2))
    artifacts = unpack_artifacts(data, tmp_path / "valid", Limits())
    assert artifacts[0].path == "result.txt"
    assert artifacts[0].size == 5
    assert len(artifacts[0].sha256) == 64
    assert (tmp_path / "valid" / "result.txt").read_bytes() == b"proof"
