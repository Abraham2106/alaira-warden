import time
from datetime import UTC, datetime
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from alaira_warden.config import Settings
from alaira_warden.correlation.engine import evaluate_snapshot
from alaira_warden.correlation.models import Context
from alaira_warden.db import connect
from alaira_warden.integration import convert
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
from alaira_warden.intelligence.http import HttpRequest
from alaira_warden.inventory import (
    AuthorizedApplication,
    InventoryLimits,
    insert_snapshot,
    snapshot_from_github,
)
from alaira_warden.inventory.github_read import HTTPResponse
from alaira_warden.orchestration.runtime import StageContext, StageOutput, WorkflowRuntime


class GitHubReader:
    """Bridge existing bounded HTTPS transport; never accepts a caller-selected API host."""

    def __init__(self, transport):
        self.transport = transport

    def request(self, method, url, headers, timeout_seconds):
        response = self.transport.send(HttpRequest(method, url, headers, None, timeout_seconds))
        return HTTPResponse(response.status_code, response.body, response.headers)


class ProductServices:
    def __init__(self, settings: Settings, transport=None):
        self.settings = settings
        self.transport = transport or UrllibTransport()

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

    def inventory_stage(self, context: StageContext):
        with connect(self.settings) as connection:
            row = connection.execute(
                "SELECT id FROM inventory_snapshots WHERE id=%s AND application_id=%s",
                (context.snapshot_id, context.application_id),
            ).fetchone()
        return (
            StageOutput(status="ready", references=(row["id"],))
            if row
            else StageOutput(status="blocked", reason="incomplete")
        )

    def sources_stage(self, context: StageContext):
        if cached := self.cached(context, "sources"):
            return cached
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
        records = [
            record
            for batch in batches
            for record in batch.records
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
        return output

    def correlation_stage(self, context: StageContext):
        if context.data_mode != self.settings.warden_data_mode:
            return StageOutput(status="blocked", reason="unsupported")
        if cached := self.cached(context, "correlation"):
            return cached
        snapshot_id = context.references["inventory"][0]
        with connect(self.settings) as connection:
            data = CaseData(self.settings, context.deadline)
            row, components = data.snapshot(connection, snapshot_id, context.application_id)
            if not row:
                return StageOutput(status="blocked", reason="incomplete")
            snapshot = convert.snapshot(row, components)
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
            output = StageOutput(status="ready", references=tuple(identifiers))
            self.save_stage(connection, context, "correlation", output)
            self.audit(
                connection, context.investigation_id, context.subject_id, "correlation.evaluated"
            )
        return output
