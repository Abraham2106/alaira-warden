"""Git object preparation on the host; all project/tool execution stays in DockerRunner.

The worker supplies an exact authorized local repository and approved tool bindings.
No repository hooks, package scripts, or model-generated commands run on the host.
"""

import hashlib
import json
import os
import re
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import UUID, uuid4

from alaira_warden.execution import DockerRunner, Job
from alaira_warden.execution.archive import FORBIDDEN, ArchiveRejected, safe_parts

REQUIRED_VALIDATIONS = ("project_tests", "syft", "trivy", "osv_scanner")
SCANNER_REPORTS = {"syft": "syft.json", "trivy": "trivy.json", "osv_scanner": "osv.json"}


@dataclass(frozen=True)
class RemediationRequest:
    application_id: UUID
    subject_id: str
    repository: Path
    base_sha: str
    package: str
    versions: tuple[str, ...]
    max_attempts: int = 2
    timeout_seconds: float = 300

    def __post_init__(self):
        if not re.fullmatch(r"[a-f0-9]{40}", self.base_sha):
            raise ValueError("A full immutable Git SHA is required")
        if not re.fullmatch(r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+", self.package):
            raise ValueError("An npm package name is required")
        if not self.versions or any(
            not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", v) for v in self.versions
        ):
            raise ValueError("Exact candidate versions are required")
        if not 1 <= self.max_attempts <= 3 or not 1 <= self.timeout_seconds <= 1800:
            raise ValueError("Finite remediation limits are required")


def _git(repository: Path, *arguments: str, data=None, environment=None) -> bytes:
    # In particular, never inherit GIT_CONFIG_COUNT, GIT_SSH_COMMAND or provider tokens.
    env = {
        k: v
        for k, v in os.environ.items()
        if k.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE"}
    }
    env.update(
        {"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    )
    env.update(environment or {})
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.attributesFile=/dev/null",
            "-C",
            str(repository),
            *arguments,
        ],
        input=data,
        capture_output=True,
        env=env,
        timeout=20,
    )
    if result.returncode:
        raise ValueError("Git object operation failed")
    return result.stdout


def _snapshot(repository: Path, sha: str, target: Path, limits):
    # Read blobs rather than git archive: export-ignore attributes must not omit test files.
    raw = _git(repository, "ls-tree", "-r", "-z", sha)
    target.mkdir(parents=True, exist_ok=False)
    count = total = 0
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        parts = safe_parts(name.decode("utf-8"))
        if any(p in FORBIDDEN or p == ".env" or p.startswith(".env.") for p in parts):
            raise ArchiveRejected("Repository contains forbidden input")
        if mode not in {"100644", "100755"} or kind != "blob":
            raise ArchiveRejected("Links, submodules and special Git entries are not accepted")
        count += 1
        total += int(_git(repository, "cat-file", "-s", blob))
        if count > limits.files or total > limits.input_bytes:
            raise ArchiveRejected("Git snapshot exceeds input budget")
        path = target.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as output:
            output.write(_git(repository, "cat-file", "blob", blob))
        path.chmod(0o755 if mode == "100755" else 0o644)


def _digest(source: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(source.rglob("*")):
        if path.is_file():
            name = path.relative_to(source).as_posix().encode()
            content = path.read_bytes()
            digest.update(len(name).to_bytes(8, "big") + name)
            digest.update(len(content).to_bytes(8, "big") + content)
    return digest.hexdigest()


def _validation_passed(validation: dict, artifact_root: Path) -> bool:
    if validation["status"] != "passed" or not validation["cleanup_succeeded"]:
        return False
    if validation["tool"] == "project_tests":
        return True
    expected = SCANNER_REPORTS[validation["tool"]]
    metadata = next((item for item in validation["artifacts"] if item["path"] == expected), None)
    if metadata is None:
        return False
    data = (artifact_root / validation["job_id"] / "files" / expected).read_bytes()
    if hashlib.sha256(data).hexdigest() != metadata["sha256"]:
        return False
    return isinstance(json.loads(data), dict)


def _commit(repository, base_sha, source, index_path):
    env = {
        "GIT_INDEX_FILE": str(index_path),
        "GIT_AUTHOR_NAME": "ALAIRA Warden",
        "GIT_AUTHOR_EMAIL": "warden@localhost",
        "GIT_COMMITTER_NAME": "ALAIRA Warden",
        "GIT_COMMITTER_EMAIL": "warden@localhost",
    }
    _git(repository, "read-tree", base_sha, environment=env)
    for name in ("package.json", "package-lock.json"):
        blob = _git(repository, "hash-object", "-w", "--stdin", data=(source / name).read_bytes())
        _git(
            repository,
            "update-index",
            "--add",
            "--cacheinfo",
            f"100644,{blob.decode().strip()},{name}",
            environment=env,
        )
    tree = _git(repository, "write-tree", environment=env).decode().strip()
    return (
        _git(
            repository,
            "-c",
            "commit.gpgSign=false",
            "commit-tree",
            tree,
            "-p",
            base_sha,
            data=b"Prepare authorized npm security update\n",
            environment=env,
        )
        .decode()
        .strip()
    )


def verify_artifact(artifact: dict, repository: Path) -> dict[str, str]:
    """Recheck a server-stored result against immutable Git objects before approval.

    This is not an attestation verifier: the caller must obtain the artefact from its
    trusted job store, never accept a client-submitted ``validated`` flag.
    """
    if artifact.get("status") != "passed" or artifact.get("validated") is not True:
        raise ValueError("Remediation was not validated")
    if artifact.get("synthetic") is not False:
        raise ValueError("Synthetic artifacts cannot authorize publication")
    base, proposed = artifact.get("base_sha", ""), artifact.get("proposed_sha", "")
    if not all(
        isinstance(value, str) and re.fullmatch(r"[a-f0-9]{40}", value)
        for value in (base, proposed)
    ):
        raise ValueError("Immutable base and proposed commits are required")
    branch = artifact.get("branch", "")
    if not isinstance(branch, str) or not re.fullmatch(r"warden/[a-f0-9]{32}", branch):
        raise ValueError("Unexpected remediation branch")
    if _git(repository, "rev-parse", "--verify", branch).decode().strip() != proposed:
        raise ValueError("Remediation branch changed")
    parents = _git(repository, "rev-list", "--parents", "-n", "1", proposed).decode().split()
    if parents != [proposed, base]:
        raise ValueError("Proposed commit does not have the pinned base parent")
    names = _git(repository, "diff", "--name-only", "-z", base, proposed).split(b"\0")
    if not set(names) - {b""} <= {b"package.json", b"package-lock.json"}:
        raise ValueError("Proposed commit changes files outside the permitted scope")
    diff = _git(
        repository,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        base,
        proposed,
        "--",
        "package.json",
        "package-lock.json",
    )
    if hashlib.sha256(diff).hexdigest() != artifact.get("diff_sha256"):
        raise ValueError("Remediation diff changed")
    expected = {item["path"]: item["sha256"] for item in artifact.get("files", [])}
    if set(expected) != {"package.json", "package-lock.json"}:
        raise ValueError("Unexpected file manifest")
    files = {}
    for name, digest in expected.items():
        data = _git(repository, "show", f"{proposed}:{name}")
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Remediation file changed")
        files[name] = data.decode("utf-8")
    attempts = artifact.get("attempts") or []
    validations = attempts[-1].get("validations", []) if attempts else []
    if (
        len(validations) != len(REQUIRED_VALIDATIONS)
        or {v["tool"] for v in validations} != set(REQUIRED_VALIDATIONS)
        or any(
            v.get("status") != "passed"
            or v.get("cleanup_succeeded") is not True
            or v.get("commit") != proposed
            or v.get("snapshot_sha256") != artifact.get("snapshot_sha256")
            for v in validations
        )
    ):
        raise ValueError("Validations do not match the proposed commit")
    return files


def remediate(
    request: RemediationRequest,
    runner: DockerRunner,
    *,
    authorized_repositories: dict[UUID, Path],
    cancel: threading.Event | None = None,
):
    """Return a serializable artefact; success requires all four real validation jobs.

    Tool contracts: npm_lockfile receives (package, exact_version), returns package.json
    and package-lock.json under artifacts/. Other tool bindings receive no arguments.
    All bindings are trusted worker policy, never accepted from a request or model.
    """
    repository = request.repository.resolve(strict=True)
    allowed = authorized_repositories.get(request.application_id)
    if allowed is None or repository != allowed.resolve(strict=True):
        raise PermissionError("Repository is not authorized for this application")
    if request.application_id not in runner.policy.allowed_applications or not request.subject_id:
        raise PermissionError("Application execution grant and actor are required")
    actual = _git(repository, "rev-parse", "--verify", f"{request.base_sha}^{{commit}}")
    if actual.decode().strip() != request.base_sha:
        raise ValueError("Base commit is unavailable")
    identifier = uuid4().hex
    artifact_dir = runner.policy.artifact_root / f"remediation-{identifier}"
    artifact_dir.mkdir(parents=True, exist_ok=False)
    cancel = cancel or threading.Event()
    timer = threading.Timer(request.timeout_seconds, cancel.set)
    timer.start()
    started = time.monotonic()
    report = {
        "id": identifier,
        "application_id": str(request.application_id),
        "actor": request.subject_id,
        "base_sha": request.base_sha,
        "branch": f"warden/{identifier}",
        "proposed_sha": None,
        "status": "blocked",
        "validated": False,
        "synthetic": False,
        "attempts": [],
        "files": [],
        "diff": None,
        "missing_tools": [
            name
            for name in ("npm_lockfile", *REQUIRED_VALIDATIONS)
            if name not in runner.policy.tools
        ],
    }

    def save():
        report["duration_seconds"] = round(time.monotonic() - started, 3)
        destination = artifact_dir / "remediation.json"
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        temporary.replace(destination)

    try:
        if report["missing_tools"]:
            save()
            return report
        for number, version in enumerate(request.versions[: request.max_attempts], 1):
            if cancel.is_set():
                report["status"] = "cancelled"
                break
            source = runner.policy.input_root / f"remediation-{identifier}-{number}"
            _snapshot(repository, request.base_sha, source, runner.policy.limits)
            attempt = {
                "number": number,
                "version": version,
                "update": None,
                "validations": [],
                "status": "running",
            }
            report["attempts"].append(attempt)
            save()
            update = runner.run(
                Job(
                    request.application_id,
                    request.subject_id,
                    source,
                    "npm_lockfile",
                    (request.package, version),
                ),
                cancel,
            )
            attempt.update({"update": asdict(update), "status": "failed"})
            if update.status != "passed" or not update.cleanup_succeeded:
                report["status"] = "cancelled" if cancel.is_set() else "failed"
                save()
                continue
            expected = {"package.json", "package-lock.json"}
            returned = {item.path for item in update.artifacts}
            if returned != expected:
                raise ValueError("npm updater did not return the exact permitted files")
            for name in expected:
                data = (runner.policy.artifact_root / update.job_id / "files" / name).read_bytes()
                metadata = next(item for item in update.artifacts if item.path == name)
                if hashlib.sha256(data).hexdigest() != metadata.sha256:
                    raise ValueError("Updater artifact integrity mismatch")
                json.loads(data)
                (source / name).write_bytes(data)
            lock = json.loads((source / "package-lock.json").read_text(encoding="utf-8"))
            if lock.get("lockfileVersion") not in {2, 3} or not any(
                path.endswith(f"node_modules/{request.package}") and item.get("version") == version
                for path, item in lock.get("packages", {}).items()
            ):
                raise ValueError("Candidate version is absent from the resolved npm lockfile")
            proposed = _commit(
                repository, request.base_sha, source, artifact_dir / f"index-{number}"
            )
            diff = _git(
                repository,
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                request.base_sha,
                proposed,
                "--",
                "package.json",
                "package-lock.json",
            ).decode("utf-8")
            if not diff:
                raise ValueError("Updater produced no change")
            before = _digest(source)
            attempt.update(
                {
                    "proposed_sha": proposed,
                    "snapshot_sha256": before,
                    "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
                }
            )
            for tool in REQUIRED_VALIDATIONS:
                if cancel.is_set():
                    break
                result = runner.run(
                    Job(request.application_id, request.subject_id, source, tool), cancel
                )
                attempt["validations"].append(
                    {"tool": tool, "commit": proposed, "snapshot_sha256": before, **asdict(result)}
                )
            passed = (
                len(attempt["validations"]) == len(REQUIRED_VALIDATIONS)
                and all(
                    _validation_passed(v, runner.policy.artifact_root)
                    for v in attempt["validations"]
                )
                and _digest(source) == before
            )
            attempt["status"] = "passed" if passed else "failed"
            report.update(
                {
                    "proposed_sha": proposed,
                    "snapshot_sha256": before,
                    "diff": diff,
                    "diff_sha256": attempt["diff_sha256"],
                    "validated": passed,
                    "status": "passed" if passed else "failed",
                    "files": [
                        {
                            "path": name,
                            "sha256": hashlib.sha256((source / name).read_bytes()).hexdigest(),
                        }
                        for name in sorted(expected)
                    ],
                }
            )
            # Create a real local branch without changing the developer checkout or invoking hooks.
            _git(repository, "update-ref", f"refs/heads/{report['branch']}", proposed)
            save()
            if passed:
                break
        if cancel.is_set():
            report["status"], report["validated"] = "cancelled", False
        elif not report["validated"]:
            report["stop_reason"] = "attempt_limit_or_candidates_exhausted"
        save()
        return report
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        report.update({"status": "failed", "validated": False, "stop_reason": type(error).__name__})
        save()
        return report
    finally:
        timer.cancel()
