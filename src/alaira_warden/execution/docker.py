import json
import os
import shutil
import subprocess
import tarfile
import threading
import time
from dataclasses import asdict
from uuid import uuid4

from alaira_warden.execution.archive import ArchiveRejected, pack_input, unpack_artifacts
from alaira_warden.execution.models import ExecutionPolicy, Job, JobResult, Tool


class DockerRunner:
    """Trusted host-side executor. Keep this object out of public request/model configuration."""

    def __init__(self, policy: ExecutionPolicy):
        self.policy = policy
        executable = shutil.which("docker")
        if not executable:
            raise RuntimeError("Docker CLI unavailable.")
        self.command = [executable, "--host", policy.docker_host]
        # Do not inherit Docker remote context, tracing credentials or provider secrets.
        self.environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE"}
        }

    def _control(self, *arguments: str, data: bytes | None = None, timeout: float = 5):
        return subprocess.run(
            [*self.command, *arguments],
            input=data,
            capture_output=True,
            timeout=timeout,
            check=True,
            env=self.environment,
        )

    def create_arguments(self, name: str, tool: Tool) -> list[str]:
        limits = self.policy.limits
        return [
            "create",
            "--name",
            name,
            "--label",
            "alaira.warden.job=true",
            "--pull=never",
            "--network=none",
            "--ipc=none",
            "--read-only",
            "--user=10001:10001",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--init",
            f"--memory={limits.memory_mb}m",
            f"--memory-swap={limits.memory_mb}m",
            f"--cpus={limits.cpus}",
            f"--pids-limit={limits.pids}",
            "--ulimit=nofile=256:256",
            "--log-driver=none",
            "--no-healthcheck",
            "--tmpfs",
            f"/workspace:rw,nosuid,nodev,size={limits.workspace_mb}m,uid=10001,gid=10001",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={limits.temporary_mb}m,uid=10001,gid=10001",
            "--workdir=/workspace",
            "--env=HOME=/tmp",
            "--env=PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint=/bin/sh",
            tool.image_id,
            "-c",
            "mkdir -p /workspace/artifacts && exec /bin/sleep infinity",
        ]

    def _verify_container(self, name: str, tool: Tool, timeout: float) -> dict:
        info = json.loads(self._control("inspect", name, timeout=timeout).stdout)[0]
        host, config = info["HostConfig"], info["Config"]
        limits = self.policy.limits
        expected = {
            "ReadonlyRootfs": True,
            "Privileged": False,
            "NetworkMode": "none",
            "IpcMode": "none",
            "Memory": limits.memory_mb * 1024 * 1024,
            "MemorySwap": limits.memory_mb * 1024 * 1024,
            "NanoCpus": int(limits.cpus * 1_000_000_000),
            "PidsLimit": limits.pids,
        }
        if any(host.get(key) != value for key, value in expected.items()):
            raise RuntimeError("Container resource or isolation policy mismatch.")
        if (
            config.get("User") != "10001:10001"
            or info.get("Image") != tool.image_id
            or host.get("Binds")
            or host.get("Devices")
            or any(mount.get("Type") != "tmpfs" for mount in info.get("Mounts", []))
            or "ALL" not in host.get("CapDrop", [])
            or "no-new-privileges:true" not in host.get("SecurityOpt", [])
        ):
            raise RuntimeError("Container privileges or mounts violate policy.")
        return {"image_id": tool.image_id, "user": config["User"], **expected}

    def _bounded_process(self, arguments, deadline, cancel, maximum):
        output = bytearray()
        exceeded = threading.Event()
        process = subprocess.Popen(
            [*self.command, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=self.environment,
            bufsize=0,
        )

        def drain():
            while chunk := process.stdout.read(8192):
                remaining = maximum - len(output)
                output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    exceeded.set()

        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        reason = None
        try:
            while process.poll() is None:
                if cancel.is_set():
                    reason = "cancelled"
                elif time.monotonic() >= deadline:
                    reason = "timed_out"
                elif exceeded.is_set():
                    reason = "output_limit"
                if reason:
                    break
                cancel.wait(min(0.05, max(0, deadline - time.monotonic())))
            if reason:
                process.kill()
            process.wait(timeout=2)
            thread.join(timeout=2)
            if thread.is_alive():
                raise RuntimeError("Output stream did not close.")
            if exceeded.is_set() and reason is None:
                reason = "output_limit"
            return process.returncode, bytes(output), reason
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            process.stdout.close()

    def run(self, job: Job, cancel: threading.Event | None = None) -> JobResult:
        if not job.subject_id.strip() or job.application_id not in self.policy.allowed_applications:
            raise PermissionError("No execution grant for this application.")
        if job.tool not in self.policy.tools:
            raise PermissionError("Tool is not approved.")
        if len(job.arguments) > 128 or any(
            "\x00" in arg or len(arg) > 65536 for arg in job.arguments
        ):
            raise ValueError("Invalid tool arguments.")
        cancel = cancel or threading.Event()
        tool = self.policy.tools[job.tool]
        started = time.monotonic()
        deadline = started + self.policy.limits.timeout_seconds
        identifier = uuid4().hex
        name = f"warden-job-{identifier}"
        directory = self.policy.artifact_root / identifier
        directory.mkdir(parents=True, exist_ok=False)
        created = False
        cleanup = True
        output = b""
        artifacts = ()
        status, exit_code, reason = "infrastructure_error", None, None
        stage = "input"
        truncated = False

        def remaining():
            if cancel.is_set():
                raise InterruptedError
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                raise TimeoutError
            return max(0.001, min(5, seconds))

        try:
            archive = pack_input(job.source, self.policy.input_root, self.policy.limits)
            stage = "execution"
            info = json.loads(
                self._control("image", "inspect", tool.image_id, timeout=remaining()).stdout
            )[0]
            if info["Id"] != tool.image_id or info.get("Config", {}).get("Volumes"):
                raise RuntimeError("Image identity or declared volumes violate policy.")
            platform = self._control("info", "--format", "{{.OSType}}", timeout=remaining())
            if platform.stdout.strip() != b"linux":
                raise RuntimeError("Linux containers are required.")
            # Set before create: reconcile removal even if the CLI loses the create response.
            created = True
            self._control(*self.create_arguments(name, tool), timeout=remaining())
            isolation = self._verify_container(name, tool, remaining())
            (directory / "isolation.json").write_text(
                json.dumps(isolation, indent=2) + "\n", encoding="utf-8"
            )
            self._control("start", name, timeout=remaining())
            # Docker cp rejects some read-only-root + tmpfs combinations. Stream the validated
            # archive through an unprivileged exec; do not relax read-only or mount the host.
            self._control(
                "exec",
                "-i",
                "--user=10001:10001",
                "--workdir=/workspace",
                name,
                "/bin/tar",
                "--no-same-owner",
                "-xf",
                "-",
                data=archive,
                timeout=remaining(),
            )
            exit_code, output, reason = self._bounded_process(
                [
                    "exec",
                    "--user=10001:10001",
                    "--workdir=/workspace",
                    name,
                    tool.executable,
                    *tool.prefix,
                    *job.arguments,
                ],
                deadline,
                cancel,
                self.policy.limits.output_bytes,
            )
            status = reason or ("passed" if exit_code == 0 else "failed")
            truncated = reason == "output_limit"
            if reason is None:
                stage = "artifacts"
                collection_code, raw, collection_reason = self._bounded_process(
                    [
                        "exec",
                        "--user=10001:10001",
                        "--workdir=/workspace",
                        name,
                        "/bin/tar",
                        "-cf",
                        "-",
                        "artifacts",
                    ],
                    deadline,
                    cancel,
                    self.policy.limits.artifact_bytes + 2 * 1024 * 1024,
                )
                if collection_reason:
                    status = (
                        "artifact_limit"
                        if collection_reason == "output_limit"
                        else collection_reason
                    )
                else:
                    if collection_code != 0:
                        raise RuntimeError("Artifact collection failed.")
                    artifacts = unpack_artifacts(raw, directory / "files", self.policy.limits)
        except (TimeoutError, subprocess.TimeoutExpired):
            status, reason = "timed_out", "Execution deadline exceeded."
        except InterruptedError:
            status, reason = "cancelled", "Execution cancelled."
        except (ArchiveRejected, tarfile.TarError) as error:
            status = "rejected" if stage == "input" else "artifact_limit"
            reason = type(error).__name__
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError, KeyError):
            # Do not echo Docker stderr or payloads: they may contain untrusted data or secrets.
            status, reason = (
                "infrastructure_error",
                "Docker operation or policy verification failed.",
            )
        finally:
            if created:
                try:
                    self._control("rm", "--force", name, timeout=5)
                except (OSError, subprocess.SubprocessError):
                    cleanup = False
                    status, reason = (
                        "infrastructure_error",
                        "Container cleanup could not be confirmed.",
                    )
        result = JobResult(
            job_id=identifier,
            application_id=job.application_id,
            subject_id=job.subject_id,
            status=status,
            exit_code=exit_code,
            output=output.decode("utf-8", errors="replace"),
            output_truncated=truncated,
            artifacts=artifacts,
            duration_seconds=round(time.monotonic() - started, 3),
            cleanup_succeeded=cleanup,
            image_id=tool.image_id,
            reason=reason,
        )
        (directory / "result.json").write_text(
            json.dumps(asdict(result), default=str, indent=2) + "\n", encoding="utf-8"
        )
        return result
