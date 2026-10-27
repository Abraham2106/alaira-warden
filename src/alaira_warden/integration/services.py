import time
from datetime import UTC, datetime
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from alaira_warden.agents import traces
from alaira_warden.config import Settings
from alaira_warden.correlation.engine import evaluate_snapshot
from alaira_warden.correlation.history import evaluate_deployment_history
from alaira_warden.correlation.models import Context
from alaira_warden.db import connect
from alaira_warden.hmem import HMEM, InvestigationMemory
from alaira_warden.integration import convert
from alaira_warden.integration.critique import run_planner_evaluator
from alaira_warden.integration.data import CaseData
from alaira_warden.intelligence import (
    SourceError,
    SourceRecord,
    UrllibTransport,
    WorkBudget,
    fetch_github_advisories,
    fetch_github_advisory,
    fetch_kev_catalog,
    fetch_nvd_cve,
    fetch_osv_vulnerability,
    group_advisories,
    persist_records,
)
from alaira_warden.intelligence.dependabot import fetch_dependabot_alert
from alaira_warden.intelligence.http import HttpRequest
from alaira_warden.inventory import (
    AuthorizedApplication,
    InventoryLimits,
    insert_snapshot,
    snapshot_from_github,
)
from alaira_warden.inventory.github_read import HTTPResponse
from alaira_warden.inventory.models import DeploymentRecord
from alaira_warden.orchestration.runtime import StageContext, StageOutput, WorkflowRuntime
from alaira_warden.providers.errors import ProviderError


class GitHubReader:
    """Bridge existing bounded HTTPS transport; never accepts a caller-selected API host."""

    def __init__(self, transport):
        self.transport = transport

    def request(self, method, url, headers, timeout_seconds):
        response = self.transport.send(HttpRequest(method, url, headers, None, timeout_seconds))
        return HTTPResponse(response.status_code, response.body, response.headers)


class ProductServices:
    def __init__(self, settings: Settings, transport=None, hmem=None, meterless=None):
        self.settings = settings
        self.transport = transport or UrllibTransport()
        persist = settings.warden_hmem_persist_dir.strip() or None
        self.hmem = hmem or HMEM({"actor": "warden", "persistDir": persist})
        self.memory = InvestigationMemory(self.hmem)
        self.meterless = meterless

    def _load_memory(self, connection):
        if not self.hmem.store.all():
            self.memory.hydrate(connection)

    def _save_memory(self, connection):
        self.memory.flush(connection)

    def runtime(self):
        return WorkflowRuntime(
            self.settings,
            {
                "inventory": self.inventory_stage,
                "sources": self.sources_stage,
                "correlation": self.correlation_stage,
            },
        )

    @staticmethod
    def application(row):
        return AuthorizedApplication(
            application_id=row["id"],
            repository=row["repository"],
            environments=tuple(row["environments"]),
            owner=row["owner"],
            criticality=row["criticality"],
        )

    def refresh(self, application: dict, ref: str, actor: str):
        result = snapshot_from_github(
            application=self.application(application),
            ref=ref,
            transport=GitHubReader(self.transport),
            allowed_repositories={application["repository"]},
            token=self.settings.warden_github_token.get_secret_value(),
            observed_at=datetime.now(UTC),
            limits=InventoryLimits(timeout_seconds=30),
        )
        with connect(self.settings) as connection:
            identifier = insert_snapshot(connection, result, actor=actor)
            self.audit(connection, application["id"], actor, "github.inventory_read")
        return {"id": identifier, **result.model_dump(mode="json")}

    def import_dependabot(self, application: dict, number: int, actor: str):
        record = fetch_dependabot_alert(
            application["repository"],
            number,
            token=self.settings.warden_github_token.get_secret_value(),
            transport=self.transport,
        )
        with connect(self.settings) as connection:
            # Serialize repeated imports for this application, including concurrent requests.
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                (f"dependabot:{application['id']}",),
            )
            persist_records(connection, [record])
            revision = connection.execute(
                "SELECT r.id FROM advisory_revisions r JOIN advisories a ON a.id=r.advisory_id "
                "WHERE a.source='github' AND a.source_identifier=%s AND r.content_hash=%s",
                (record.source_id, record.content_hash),
            ).fetchone()["id"]
            row = connection.execute(
                "SELECT * FROM investigations WHERE application_id=%s AND source_url=%s "
                "ORDER BY created_at,id LIMIT 1",
                (application["id"], record.source_url),
            ).fetchone()
            created = row is None
            if created:
                row = connection.execute(
                    "INSERT INTO investigations(id,application_id,title,source_url,description) "
                    "VALUES (%s,%s,%s,%s,%s) RETURNING *",
                    (
                        uuid4(),
                        application["id"],
                        record.title or "Dependabot alert",
                        record.source_url,
                        record.summary or "Dependabot intake; exposure unverified.",
                    ),
                ).fetchone()
            if not connection.execute(
                "SELECT id FROM evidence WHERE investigation_id=%s AND advisory_revision_id=%s",
                (row["id"], revision),
            ).fetchone():
                connection.execute(
                    "INSERT INTO evidence(id,investigation_id,advisory_revision_id,source_url,"
                    "content_hash,excerpt,confidence) VALUES (%s,%s,%s,%s,%s,%s,'preliminary')",
                    (
                        uuid4(),
                        row["id"],
                        revision,
                        record.source_url,
                        record.content_hash,
                        (record.summary or "")[:4000],
                    ),
                )
            self.audit(connection, row["id"], actor, "dependabot.imported")
        return {
            "investigation": row,
            "created": created,
            "advisory_identifier": record.aliases[0],
            "alert_state": record.origin["state"],
            "warnings": record.warnings,
        }

    @staticmethod
    def audit(connection, identifier, actor, action):
        connection.execute(
            "INSERT INTO audit_events(entity_id,actor,action) VALUES (%s,%s,%s)",
            (identifier, actor, action),
        )

    def cached(self, context, stage):
        with connect(self.settings) as connection:
            row = connection.execute(
                "SELECT payload FROM workflow_stage_results WHERE run_id=%s AND stage=%s",
                (context.run_id, stage),
            ).fetchone()
            return StageOutput.model_validate(row["payload"]) if row else None

    @staticmethod
    def save_stage(connection, context, stage, output):
        connection.execute(
            "INSERT INTO workflow_stage_results(run_id,stage,payload) VALUES (%s,%s,%s) "
            "ON CONFLICT DO NOTHING",
            (context.run_id, stage, Jsonb(output.model_dump(mode="json"))),
        )

    def narrate(self, context: StageContext, agent: str, status: str, summary: str, **detail):
        traces.emit(
            self.settings,
            investigation_id=context.investigation_id,
            run_id=context.run_id,
            agent=agent,
            stage=(
                context.idempotency_key.split(":")[1] if ":" in context.idempotency_key else "run"
            ),
            status=status,
            summary=summary,
            detail=detail,
        )

    def inventory_stage(self, context: StageContext):
        self.narrate(context, "cartographer", "started", "Reading the pinned snapshot.")
        if not context.snapshot_id:
            self.narrate(context, "cartographer", "blocked", "No snapshot pinned.")
            return StageOutput(status="blocked", reason="incomplete")
        row = None
        with connect(self.settings) as connection:
            try:
                data = CaseData(self.settings, context.deadline)
                row, _components = data.snapshot(
                    connection, context.snapshot_id, context.application_id
                )
            except (ProviderError, ValueError):
                reason = (
                    "unsupported" if self.settings.warden_data_mode == "zetaris" else "incomplete"
                )
                self.narrate(
                    context,
                    "cartographer",
                    "blocked",
                    "Incomplete inventory or Zetaris failed closed.",
                    reason=reason,
                )
                return StageOutput(status="blocked", reason=reason)
        if not row:
            self.narrate(context, "cartographer", "blocked", "Snapshot is out of scope.")
            return StageOutput(status="blocked", reason="incomplete")
        self.narrate(
            context,
            "cartographer",
            "handed_off",
            "Snapshot ready. Handoff to Scout.",
            snapshot_id=str(row["id"]),
        )
        return StageOutput(status="ready", references=(UUID(str(row["id"])),))

    def sources_stage(self, context: StageContext):
        if cached := self.cached(context, "sources"):
            return cached
        self.narrate(context, "scout", "started", "Querying GitHub, OSV, NVD, and KEV.")
        seconds = max(0.1, context.deadline - time.monotonic() - 1)
        budget = WorkBudget(
            max_requests=8,
            max_retries=0,
            timeout_seconds=min(8, seconds),
            deadline_seconds=seconds,
            max_wait_seconds=0,
        )
        identifier = context.advisory_identifier
        batches, errors = [], []

        def fetch(call, **kwargs):
            if context.cancelled():
                return
            try:
                batch = call(transport=self.transport, budget=budget, **kwargs)
                batches.append(batch)
            except SourceError as error:
                errors.append({"source": error.source, "category": error.category})

        if identifier.startswith("GHSA-"):
            fetch(
                fetch_github_advisory,
                ghsa_id=identifier,
                github_token=self.settings.warden_github_token.get_secret_value(),
            )
        else:
            fetch(
                fetch_github_advisories,
                cve_id=identifier,
                github_token=self.settings.warden_github_token.get_secret_value(),
            )
        fetch(fetch_osv_vulnerability, vulnerability_id=identifier)
        records = [record for batch in batches for record in batch.records]
        cves = {
            alias
            for record in records
            for alias in [record.source_id, *record.aliases]
            if alias.startswith("CVE-")
        }
        if identifier.startswith("CVE-"):
            cves.add(identifier)
        if cves:
            # One bounded CVE enrichment per dispatch; additional aliases remain explicit.
            cve = sorted(cves)[0]
            fetch(
                fetch_nvd_cve,
                cve_id=cve,
                nvd_api_key=self.settings.warden_nvd_api_key.get_secret_value() or None,
                include_changes=False,
            )
            fetch(fetch_kev_catalog)
        relevant = {identifier, *cves}
        with connect(self.settings) as connection:
            imported = connection.execute(
                "SELECT r.payload FROM evidence e JOIN advisory_revisions r "
                "ON r.id=e.advisory_revision_id WHERE e.investigation_id=%s "
                "AND r.payload->'origin'->>'provider'='dependabot' "
                "ORDER BY r.retrieved_at DESC LIMIT 100",
                (context.investigation_id,),
            ).fetchall()
        records = [
            record
            for record in [
                *[record for batch in batches for record in batch.records],
                *[SourceRecord.model_validate(row["payload"]) for row in imported],
            ]
            if relevant.intersection({record.source_id, *record.aliases})
        ]
        if not records:
            with connect(self.settings) as connection:
                connection.execute(
                    "INSERT INTO workflow_stage_results(run_id,stage,payload) VALUES (%s,%s,%s)",
                    (
                        context.run_id,
                        f"consultation:{uuid4()}",
                        Jsonb(
                            {"errors": errors, "warnings": ["no_records_is_not_a_negative_finding"]}
                        ),
                    ),
                )
            return StageOutput(status="retryable", reason="unavailable")
        grouping = group_advisories(records)
        revisions = []
        with connect(self.settings) as connection:
            persist_records(connection, records)
            for record in records:
                row = connection.execute(
                    "SELECT r.id FROM advisory_revisions r JOIN advisories a ON a.id=r.advisory_id "
                    "WHERE a.source=%s AND a.source_identifier=%s AND r.content_hash=%s",
                    (record.source, record.source_id, record.content_hash),
                ).fetchone()
                revision = row["id"]
                if revision in revisions:
                    continue
                revisions.append(revision)
                connection.execute(
                    "INSERT INTO evidence(id,investigation_id,advisory_revision_id,source_url,"
                    "content_hash,excerpt,confidence) VALUES (%s,%s,%s,%s,%s,%s,'preliminary')",
                    (
                        uuid4(),
                        context.investigation_id,
                        revision,
                        record.source_url or "",
                        record.content_hash,
                        (record.summary or record.title or "")[:4000],
                    ),
                )
                self.audit(
                    connection,
                    context.investigation_id,
                    context.subject_id,
                    f"source.{record.source}.retrieved",
                )
            self._load_memory(connection)
            for record in records:
                self.memory.remember_source(
                    record, context.investigation_id, context.advisory_identifier
                )
            self._save_memory(connection)
            output = StageOutput(status="ready", references=tuple(revisions))
            self.save_stage(connection, context, "sources", output)
            # Keep source completeness/errors and alias reasoning alongside the case.
            connection.execute(
                "INSERT INTO workflow_stage_results(run_id,stage,payload) "
                "VALUES (%s,'consultation',%s)",
                (
                    context.run_id,
                    Jsonb(
                        {
                            "groups": grouping.model_dump(mode="json"),
                            "errors": errors,
                            "batches": [
                                {
                                    "source": b.source,
                                    "complete": b.complete,
                                    "warnings": b.warnings,
                                    "next_cursor": b.next_cursor,
                                }
                                for b in batches
                            ],
                        }
                    ),
                ),
            )
        self.narrate(
            context,
            "scout",
            "handed_off" if output.status == "ready" else "failed",
            "Evidence persisted." if output.status == "ready" else "Sources incomplete.",
            errors=errors,
        )
        return output

    def correlation_stage(self, context: StageContext):
        if context.data_mode != self.settings.warden_data_mode:
            return StageOutput(status="blocked", reason="unsupported")
        if cached := self.cached(context, "correlation"):
            self.critique_stage(context, cached.references)
            return cached
        snapshot_id = context.references["inventory"][0]
        with connect(self.settings) as connection:
            data = CaseData(self.settings, context.deadline)
            row, components = data.snapshot(connection, snapshot_id, context.application_id)
            if not row:
                return StageOutput(status="blocked", reason="incomplete")
            snapshot = convert.snapshot(row, components)
            self._load_memory(connection)
            packages = " ".join(dict.fromkeys(item.name for item in snapshot.components))
            authorized_cases = connection.execute(
                "SELECT id FROM investigations WHERE application_id=%s", (context.application_id,)
            ).fetchall()
            recall = self.memory.recall_for_cases(
                f"{context.advisory_identifier} {packages}".strip(),
                [str(item["id"]) for item in authorized_cases],
            )
            self.memory.save_recall(connection, context.investigation_id, context.run_id, recall)
            self.narrate(
                context,
                "mnemonic",
                "decided" if recall.get("available") else "skipped",
                "H-MEM recall ready." if recall.get("available") else "No prior recall.",
                available=bool(recall.get("available")),
            )
            app = connection.execute(
                "SELECT criticality FROM applications WHERE id=%s", (context.application_id,)
            ).fetchone()
            identifiers = []
            for revision in context.references["sources"]:
                payload = data.advisory(connection, revision, context.investigation_id)
                review = connection.execute(
                    "SELECT id,confidence FROM evidence_reviews WHERE investigation_id=%s "
                    "AND advisory_revision_id=%s ORDER BY created_at DESC,id DESC LIMIT 1",
                    (context.investigation_id, revision),
                ).fetchone()
                record = SourceRecord.model_validate(payload)
                advisory = convert.advisory(
                    record, review["confidence"] if review else "preliminary"
                )
                assessment = evaluate_snapshot(
                    snapshot,
                    advisory,
                    Context(
                        application_id=context.application_id,
                        snapshot_id=snapshot.id,
                        asset_criticality=app["criticality"] or "medium",
                    ),
                )
                deployment_rows = connection.execute(
                    "SELECT application_id,environment,artifact_ref,commit_sha,snapshot_id,"
                    "deployed_at,retired_at,source_reference FROM deployments "
                    "WHERE application_id=%s ORDER BY deployed_at DESC LIMIT 1001",
                    (context.application_id,),
                ).fetchall()
                deployments = [DeploymentRecord.model_validate(item) for item in deployment_rows]
                historical = []
                for candidate in connection.execute(
                    "SELECT DISTINCT s.id FROM inventory_snapshots s JOIN deployments d "
                    "ON d.application_id=s.application_id AND (d.snapshot_id=s.id OR "
                    "(d.snapshot_id IS NULL AND d.commit_sha=s.commit_ref)) "
                    "WHERE s.application_id=%s LIMIT 1001",
                    (context.application_id,),
                ).fetchall():
                    hrow, hcomponents = data.snapshot(
                        connection, candidate["id"], context.application_id
                    )
                    historical.append(convert.snapshot(hrow, hcomponents))
                history = evaluate_deployment_history(
                    snapshot,
                    advisory,
                    deployments,
                    historical,
                    asset_criticality=app["criticality"] or "medium",
                )
                connection.execute(
                    "INSERT INTO workflow_stage_results(run_id,stage,payload) VALUES (%s,%s,%s) "
                    "ON CONFLICT DO NOTHING",
                    (context.run_id, f"history:{revision}", Jsonb(history.model_dump(mode="json"))),
                )
                for observation in history.deployments:
                    if observation.assessment is not None:
                        historical_assessment = observation.assessment
                        connection.execute(
                            "INSERT INTO assessments(id,investigation_id,snapshot_id,"
                            "advisory_revision_id,payload,data_layer,data_sources,review_id) "
                            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                            (
                                uuid4(),
                                context.investigation_id,
                                historical_assessment.snapshot_id,
                                revision,
                                Jsonb(historical_assessment.model_dump(mode="json")),
                                data.mode,
                                Jsonb(list(data.sources)),
                                review["id"] if review else None,
                            ),
                        )
                assessment_id = uuid4()
                connection.execute(
                    "INSERT INTO assessments(id,investigation_id,snapshot_id,advisory_revision_id,"
                    "payload,data_layer,data_sources,review_id) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        assessment_id,
                        context.investigation_id,
                        snapshot.id,
                        revision,
                        Jsonb(assessment.model_dump(mode="json")),
                        data.mode,
                        Jsonb(list(data.sources)),
                        review["id"] if review else None,
                    ),
                )
                for finding in assessment.findings:
                    connection.execute(
                        "INSERT INTO findings(id,investigation_id,component_id,"
                        "advisory_revision_id,"
                        "exposure,policy_version,priority,justification,conditions) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (
                            uuid4(),
                            context.investigation_id,
                            UUID(finding.component_id),
                            revision,
                            finding.exposure,
                            assessment.policy_version,
                            finding.priority,
                            ", ".join(finding.reasons) or "explicit_version_evaluation",
                            Jsonb(finding.model_dump(mode="json")),
                        ),
                    )
                identifiers.append(assessment_id)
                self.memory.remember_assessment(
                    assessment,
                    context.investigation_id,
                    context.advisory_identifier,
                    str(revision),
                )
            self._save_memory(connection)
            self.narrate(
                context,
                "arbiter",
                "decided",
                "Deterministic exposure recorded. The model does not assign it.",
                assessments=len(identifiers),
            )
            output = StageOutput(status="ready", references=tuple(identifiers))
            self.save_stage(connection, context, "correlation", output)
            self.audit(
                connection, context.investigation_id, context.subject_id, "correlation.evaluated"
            )
        self.critique_stage(context, identifiers)
        return output

    def critique_stage(self, context, identifiers):
        """Assessments commit first; each model reservation commits independently."""
        with connect(self.settings) as connection:
            if connection.execute(
                "SELECT 1 FROM workflow_stage_results WHERE run_id=%s AND stage='critique'",
                (context.run_id,),
            ).fetchone():
                return
            rows = connection.execute(
                "SELECT id,payload FROM assessments WHERE investigation_id=%s "
                "AND id=ANY(%s::uuid[]) ORDER BY id",
                (context.investigation_id, list(identifiers)),
            ).fetchall()
            saved = connection.execute(
                "SELECT payload FROM workflow_stage_results WHERE run_id=%s "
                "AND stage LIKE 'critique_state:%%' ORDER BY created_at DESC,stage DESC LIMIT 1",
                (context.run_id,),
            ).fetchone()
        facts = [
            {
                "id": str(row["id"]),
                "exposure": row["payload"].get("exposure"),
                "findings": [
                    {
                        "package": finding.get("package_name"),
                        "version": finding.get("resolved_version"),
                        "reasons": finding.get("reasons", [])[:3],
                    }
                    for finding in row["payload"].get("findings", [])[:4]
                ],
            }
            for row in rows[:6]
        ]

        def checkpoint(payload):
            with connect(self.settings) as connection:
                connection.execute(
                    "INSERT INTO workflow_stage_results(run_id,stage,payload) VALUES (%s,%s,%s)",
                    (context.run_id, f"critique_state:{time.time_ns()}", Jsonb(payload)),
                )

        critique = run_planner_evaluator(
            self.settings,
            assessment_ids=identifiers,
            client=self.meterless,
            context={"assessments": facts},
            state=saved["payload"] if saved else None,
            checkpoint=checkpoint,
            cancelled=context.cancelled,
            deadline=context.deadline,
        )
        with connect(self.settings) as connection:
            connection.execute(
                "INSERT INTO workflow_stage_results(run_id,stage,payload) "
                "VALUES (%s,'critique',%s) "
                "ON CONFLICT DO NOTHING",
                (context.run_id, Jsonb(critique)),
            )
        self.narrate(
            context,
            "evaluator",
            "decided" if critique.get("status") == "ready" else "blocked",
            "Plan review recorded. Deterministic exposure is unchanged.",
            critique_status=critique.get("status"),
            changed_exposure=False,
        )
