"""Persistent product execution: server-owned repository, tools and approval records."""

import base64
import hashlib
import json
import os
import re
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from alaira_warden.db import connect
from alaira_warden.execution import DockerRunner, ExecutionPolicy, Limits
from alaira_warden.identity import PostgresIdentityStore, Principal, audit_actor, authorize
from alaira_warden.publication import GitHubPublisher, approve
from alaira_warden.remediation import RemediationRequest, remediate, verify_artifact
from alaira_warden.remediation.tools import npm_tools, scanner_tools


class ProductActions:
    def __init__(self, settings, runner_factory=None, publisher_factory=None):
        self.settings = settings
        self.runner_factory = runner_factory
        self.publisher_factory = publisher_factory

    def fresh(self, subject_id):
        with connect(self.settings) as connection:
            subject = next(
                (
                    s
                    for s in PostgresIdentityStore(connection).list_subjects()
                    if s.subject_id == UUID(str(subject_id))
                ),
                None,
            )
        if subject is None:
            raise PermissionError("Subject no longer exists")
        return Principal(
            subject_id=subject.subject_id,
            is_active=subject.is_active,
            authentication_method="api_credential",
            assignments=subject.assignments,
        )

    def permit(self, principal, action, application_id):
        current = self.fresh(principal.subject_id)
        if not authorize(current, action, UUID(str(application_id))).allowed:
            raise PermissionError("Action is no longer authorized")
        return current

    def repository(self, application, base_sha):
        name = application["repository"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name) or any(
            part in {".", ".."} for part in name.split("/")
        ):
            raise ValueError("Invalid authorized repository")
        root = Path(self.settings.warden_repository_root).resolve()
        root.mkdir(parents=True, exist_ok=True)
        path = root / str(application["id"])
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("Repository escaped server root")
        env = {
            k: v
            for k, v in os.environ.items()
            if k.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
        }
        env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        token = self.settings.warden_github_token.get_secret_value()
        if token:
            header = base64.b64encode(f"x-access-token:{token}".encode()).decode()
            env.update(
                GIT_CONFIG_COUNT="1",
                GIT_CONFIG_KEY_0="http.https://github.com/.extraHeader",
                GIT_CONFIG_VALUE_0=f"Authorization: Basic {header}",
            )

        def git(*args):
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "http.followRedirects=false",
                    "-c",
                    "credential.helper=",
                    *args,
                ],
                env=env,
                capture_output=True,
                timeout=120,
            )
            if result.returncode:
                raise ValueError("Authorized GitHub checkout failed")

        # No hooks, smudge filters or project code run on the host.
        if not path.exists():
            git("clone", "--bare", f"https://github.com/{name}.git", str(path))
        git("-C", str(path), "fetch", "--no-tags", f"https://github.com/{name}.git", base_sha)
        return path

    def runner(self, application_id):
        if self.runner_factory:
            return self.runner_factory(application_id)
        image = self.settings.warden_remediation_image
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
            raise ValueError("Operator must configure an immutable remediation tool image")
        root = Path(self.settings.warden_execution_root).resolve()
        inputs, outputs = root / "inputs", root / "jobs"
        inputs.mkdir(parents=True, exist_ok=True)
        outputs.mkdir(parents=True, exist_ok=True)
        tools = {
            **npm_tools(image),
            **scanner_tools(syft_image=image, trivy_image=image, osv_image=image),
        }
        return DockerRunner(
            ExecutionPolicy(
                inputs,
                outputs,
                frozenset({application_id}),
                tools,
                Limits(
                    memory_mb=2048,
                    temporary_mb=64,
                    workspace_mb=128,
                    timeout_seconds=180,
                    files=1024,
                    artifact_bytes=16 * 1024 * 1024,
                ),
            )
        )

    def audit(self, case_id, actor, action):
        with connect(self.settings) as connection:
            connection.execute(
                "INSERT INTO audit_events(entity_id,actor,action) VALUES (%s,%s,%s)",
                (case_id, actor, action),
            )

    @contextmanager
    def case_lock(self, case_id):
        with connect(self.settings) as connection:
            key = f"productcase:{case_id}"
            if not connection.execute(
                "SELECT pg_try_advisory_lock(hashtextextended(%s,0)) AS ok", (key,)
            ).fetchone()["ok"]:
                raise ValueError("Another correction or publication is running for this case")
            try:
                row = connection.execute(
                    "SELECT status FROM investigations WHERE id=%s", (case_id,)
                ).fetchone()
                if not row or row["status"] in {"closed", "cancelled"}:
                    raise ValueError("Case is closed")
                yield
            finally:
                connection.execute("SELECT pg_advisory_unlock(hashtextextended(%s,0))", (key,))

    def execute(self, case, application, payload, principal):
        with self.case_lock(case["id"]):
            return self._execute(case, application, payload, principal)

    def _execute(self, case, application, payload, principal):
        principal = self.permit(principal, "patch.prepare", application["id"])
        inputs = payload.model_dump(mode="json")
        with connect(self.settings) as connection:
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                (f"remediation:{case['id']}",),
            )
            existing = connection.execute(
                "SELECT * FROM product_jobs WHERE investigation_id=%s AND request_key=%s",
                (case["id"], payload.request_key),
            ).fetchone()
            if existing:
                if existing["input"] != inputs:
                    raise ValueError("Request key already belongs to a different input")
                return self.public_job(existing)
            if connection.execute(
                "SELECT 1 FROM product_jobs WHERE investigation_id=%s AND status='running'",
                (case["id"],),
            ).fetchone():
                raise ValueError(
                    "A remediation is running or interrupted; inspect it before retrying"
                )
            snapshot = connection.execute(
                "SELECT commit_ref FROM inventory_snapshots WHERE id=%s AND application_id=%s",
                (payload.snapshot_id, application["id"]),
            ).fetchone()
            if not snapshot:
                raise ValueError("Snapshot does not belong to this application")
            plan = connection.execute(
                "SELECT id,payload FROM investigation_plans WHERE investigation_id=%s "
                "ORDER BY created_at DESC LIMIT 1",
                (case["id"],),
            ).fetchone()
            if not plan or plan["payload"].get("action") != "update_dependency":
                raise ValueError("An update plan is required before execution")
            job_id = uuid4()
            connection.execute(
                "INSERT INTO product_jobs(id,investigation_id,request_key,actor,input,status) "
                "VALUES (%s,%s,%s,%s,%s,'running')",
                (job_id, case["id"], payload.request_key, audit_actor(principal), Jsonb(inputs)),
            )
        try:
            runner = self.runner(application["id"])
            repository = self.repository(application, snapshot["commit_ref"])
            service = self

            class Cancellation(threading.Event):
                def __init__(self):
                    super().__init__()
                    self.checked = 0.0

                def is_set(self):
                    if not super().is_set() and time.monotonic() - self.checked > 1:
                        self.checked = time.monotonic()
                        with connect(service.settings) as state_connection:
                            state = state_connection.execute(
                                "SELECT status FROM product_jobs WHERE id=%s",
                                (job_id,),
                            ).fetchone()
                        if not state or state["status"] == "cancelled":
                            self.set()
                    return super().is_set()

            result = remediate(
                RemediationRequest(
                    application["id"],
                    audit_actor(principal),
                    repository,
                    snapshot["commit_ref"],
                    payload.package,
                    tuple(payload.versions),
                    max_attempts=payload.max_attempts,
                    timeout_seconds=900,
                ),
                runner,
                authorized_repositories={application["id"]: repository},
                cancel=Cancellation(),
            )
            status = (
                result["status"]
                if result["status"] in {"passed", "failed", "cancelled"}
                else "blocked"
            )
        except (ValueError, PermissionError, OSError, RuntimeError, subprocess.SubprocessError):
            result, status = (
                {
                    "status": "blocked",
                    "validated": False,
                    "synthetic": False,
                    "reason": "execution_configuration_or_repository_failed",
                },
                "blocked",
            )
        result = json.loads(json.dumps(result, default=str))
        with connect(self.settings) as connection:
            connection.execute(
                "UPDATE product_jobs SET status=%s,payload=%s,updated_at=now() WHERE id=%s",
                (status, Jsonb(result), job_id),
            )
            # Existing case views/reports consume the real artifact and all scanner results.
            patch_id = uuid4()
            digest = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
            connection.execute(
                "INSERT INTO investigation_patches(id,investigation_id,plan_id,actor,"
                "payload,content_hash) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (patch_id, case["id"], plan["id"], audit_actor(principal), Jsonb(result), digest),
            )
            validations = (
                result.get("attempts", [{}])[-1].get("validations", [])
                if result.get("attempts")
                else []
            )
            connection.execute(
                "INSERT INTO investigation_validations(id,investigation_id,patch_id,actor,payload) "
                "VALUES (%s,%s,%s,%s,%s)",
                (
                    uuid4(),
                    case["id"],
                    patch_id,
                    audit_actor(principal),
                    Jsonb(
                        {
                            "commit": result.get("proposed_sha"),
                            "overall": status,
                            "approved": result.get("validated", False),
                            "synthetic": False,
                            "results": validations,
                        }
                    ),
                ),
            )
        self.audit(case["id"], audit_actor(principal), "remediation." + status)
        return {"id": str(job_id), "status": status, "payload": result}

    @staticmethod
    def public_job(row):
        return {"id": str(row["id"]), "status": row["status"], "payload": row["payload"]}

    def job(self, case_id, job_id):
        with connect(self.settings) as connection:
            row = connection.execute(
                "SELECT * FROM product_jobs WHERE id=%s AND investigation_id=%s", (job_id, case_id)
            ).fetchone()
        if not row:
            raise ValueError("Remediation not found in this case")
        return row

    def cancel(self, case, application, job_id, principal):
        principal = self.permit(principal, "patch.prepare", application["id"])
        self.job(case["id"], job_id)
        with connect(self.settings) as connection:
            connection.execute(
                "UPDATE product_jobs SET status='cancelled',updated_at=now() "
                "WHERE id=%s AND investigation_id=%s AND status='running'",
                (job_id, case["id"]),
            )
        self.audit(case["id"], audit_actor(principal), "remediation.cancel_requested")
        return {"cancel_requested": True, "id": str(job_id)}

    def require_current(self, case_id, job_id):
        with connect(self.settings) as connection:
            latest = connection.execute(
                "SELECT id FROM product_jobs WHERE investigation_id=%s "
                "ORDER BY created_at DESC,id DESC LIMIT 1",
                (case_id,),
            ).fetchone()
        if not latest or latest["id"] != job_id:
            raise ValueError("A newer artifact exists; the prior approval is obsolete")

    def review(self, case, application, job_id, payload, principal):
        with self.case_lock(case["id"]):
            return self._review(case, application, job_id, payload, principal)

    def _review(self, case, application, job_id, payload, principal):
        principal = self.permit(principal, "approval.decide", application["id"])
        self.require_current(case["id"], job_id)
        row = self.job(case["id"], job_id)
        result = approve(
            row["payload"],
            application["repository"],
            payload.base,
            principal=principal,
            justification=payload.justification,
        )
        if payload.decision == "rejected":
            result.update(decision="rejected", valid=False)
        with connect(self.settings) as connection:
            connection.execute(
                "INSERT INTO product_approvals(id,job_id,payload) VALUES (%s,%s,%s)",
                (UUID(result["id"]), job_id, Jsonb(result)),
            )
        self.audit(case["id"], audit_actor(principal), "artifact." + payload.decision)
        return result

    def publish(self, case, application, job_id, principal):
        publisher = self.permit(principal, "pull_request.publish", application["id"])
        # Session lock spans network calls; audit uses independent committed transactions.
        with connect(self.settings) as lock:
            acquired = lock.execute(
                "SELECT pg_try_advisory_lock(hashtextextended(%s,0)) AS ok",
                (f"productcase:{case['id']}",),
            ).fetchone()["ok"]
            if not acquired:
                raise ValueError("Publication is already running")
            try:
                current = lock.execute(
                    "SELECT status FROM investigations WHERE id=%s", (case["id"],)
                ).fetchone()
                if not current or current["status"] in {"closed", "cancelled"}:
                    raise ValueError("Case is closed")
                self.require_current(case["id"], job_id)
                row = self.job(case["id"], job_id)
                approval = lock.execute(
                    "SELECT payload FROM product_approvals WHERE job_id=%s "
                    "ORDER BY created_at DESC LIMIT 1",
                    (job_id,),
                ).fetchone()
                if not approval:
                    raise ValueError("Approve the exact validated artifact before publication")
                approval = approval["payload"]
                approver = self.fresh(approval["subject_id"])
                repository = Path(self.settings.warden_repository_root).resolve() / str(
                    application["id"]
                )
                verify_artifact(row["payload"], repository)
                factory = self.publisher_factory or GitHubPublisher
                result = factory(self.settings.warden_github_token.get_secret_value()).publish(
                    row["payload"],
                    approval,
                    repository=application["repository"],
                    base=approval["base"],
                    approver=approver,
                    publisher=publisher,
                    local_repository=repository,
                    authorized_repository=repository,
                    audit=lambda action, detail: self.audit(
                        case["id"], audit_actor(publisher), str(action)
                    ),
                )
                with connect(self.settings) as connection:
                    connection.execute(
                        "INSERT INTO product_publications(id,job_id,payload) VALUES (%s,%s,%s)",
                        (uuid4(), job_id, Jsonb(result)),
                    )
                return result
            finally:
                lock.execute(
                    "SELECT pg_advisory_unlock(hashtextextended(%s,0))",
                    (f"productcase:{case['id']}",),
                )
