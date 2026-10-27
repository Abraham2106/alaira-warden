"""Prove a Warden investigation read of inventory and evidence through Zetaris."""

from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from psycopg.types.json import Jsonb

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from alaira_warden.config import Settings  # noqa: E402
from alaira_warden.correlation.engine import evaluate_snapshot  # noqa: E402
from alaira_warden.correlation.models import Context  # noqa: E402
from alaira_warden.db import connect  # noqa: E402
from alaira_warden.integration import convert  # noqa: E402
from alaira_warden.integration.data import CaseData  # noqa: E402
from alaira_warden.intelligence import SourceRecord  # noqa: E402
from alaira_warden.intelligence.models import AffectedEntry, Attribution  # noqa: E402


def seed_if_needed(settings: Settings) -> tuple[str, str, str]:
    owner = settings.model_copy(
        update={"warden_database_url": settings.warden_migration_database_url}
    )
    with connect(owner) as connection:
        existing = connection.execute(
            "SELECT s.id AS snapshot_id, s.application_id, r.id AS revision_id, e.investigation_id "
            "FROM inventory_snapshots s "
            "JOIN investigations i ON i.application_id=s.application_id "
            "JOIN evidence e ON e.investigation_id=i.id "
            "JOIN advisory_revisions r ON r.id=e.advisory_revision_id "
            "LIMIT 1"
        ).fetchone()
        if existing:
            return (
                str(existing["snapshot_id"]),
                str(existing["application_id"]),
                str(existing["revision_id"]),
            )
        application_id, snapshot_id, investigation_id = uuid4(), uuid4(), uuid4()
        component_id, advisory_id, revision_id, evidence_id = uuid4(), uuid4(), uuid4(), uuid4()
        connection.execute(
            "INSERT INTO applications(id,name,repository,owner,criticality,environments) "
            "VALUES (%s,'Zetaris e2e','zetaris/e2e','warden','medium',%s)",
            (application_id, Jsonb(["production"])),
        )
        connection.execute(
            "INSERT INTO inventory_snapshots(id,application_id,commit_ref,tool_name,tool_version,"
            "completeness) VALUES (%s,%s,%s,'syft','test','complete')",
            (snapshot_id, application_id, "a" * 40),
        )
        connection.execute(
            "INSERT INTO components(id,snapshot_id,name,ecosystem,resolved_version,direct,"
            "dependency_paths) VALUES (%s,%s,'lodash','npm','4.17.20',TRUE,%s)",
            (component_id, snapshot_id, Jsonb([["lodash@4.17.20"]])),
        )
        connection.execute(
            "INSERT INTO investigations(id,application_id,title,description,source_url,status) "
            "VALUES (%s,%s,'Zetaris e2e','Pinned views','https://github.com/advisories/GHSA-35jh-r3h4-6jhm',"
            "'detected')",
            (investigation_id, application_id),
        )
        payload = SourceRecord(
            source="github",
            source_id="GHSA-35jh-r3h4-6jhm",
            aliases=["CVE-2020-8203"],
            title="Zetaris e2e",
            summary="Pinned advisory for the data layer",
            retrieved_at=datetime.now(UTC),
            content_hash="b" * 64,
            affected=[
                AffectedEntry(
                    ecosystem="npm",
                    package_name="lodash",
                    ranges=[
                        {
                            "type": "github_vulnerable_version_range",
                            "vulnerable_version_range": "<4.17.21",
                        }
                    ],
                    versions=[],
                )
            ],
            affected_complete=True,
            attribution=Attribution(
                provider="github",
                documentation_url="https://docs.github.com/en/rest",
                notes="Synthetic Zetaris data-layer fixture",
            ),
            origin={"fixture": "zetaris-e2e"},
        ).model_dump(mode="json")
        connection.execute(
            "INSERT INTO advisories(id,source,source_identifier,aliases) "
            "VALUES (%s,'github',%s,%s)",
            (advisory_id, "GHSA-35jh-r3h4-6jhm", Jsonb(["CVE-2020-8203"])),
        )
        connection.execute(
            "INSERT INTO advisory_revisions(id,advisory_id,content_hash,payload) "
            "VALUES (%s,%s,%s,%s)",
            (revision_id, advisory_id, "b" * 64, Jsonb(payload)),
        )
        connection.execute(
            "INSERT INTO evidence(id,investigation_id,advisory_revision_id,source_url,confidence) "
            "VALUES (%s,%s,%s,'https://github.com/advisories/GHSA-35jh-r3h4-6jhm','preliminary')",
            (evidence_id, investigation_id, revision_id),
        )
        return str(snapshot_id), str(application_id), str(revision_id)


def main() -> int:
    settings = Settings(_env_file=ROOT / ".env")
    if settings.warden_data_mode != "zetaris":
        raise SystemExit("WARDEN_DATA_MODE must be zetaris after register_zetaris_data_layer.py")
    snapshot_id, application_id, revision_id = seed_if_needed(settings)
    with connect(settings) as connection:
        case = connection.execute(
            "SELECT investigation_id FROM warden_evidence_data WHERE revision_id=%s LIMIT 1",
            (revision_id,),
        ).fetchone()
        if not case:
            raise SystemExit("Evidence view is empty after seed")
        data = CaseData(settings, time.monotonic() + 60)
        row, components = data.snapshot(connection, snapshot_id, application_id)
        payload = data.advisory(connection, revision_id, case["investigation_id"])
        snapshot = convert.snapshot(row, components)
        advisory = convert.advisory(SourceRecord.model_validate(payload), "preliminary")
        assessment = evaluate_snapshot(
            snapshot,
            advisory,
            Context(
                application_id=application_id,
                snapshot_id=snapshot.id,
                asset_criticality="medium",
            ),
        )
        assessment_id = uuid4()
        connection.execute(
            "INSERT INTO assessments(id,investigation_id,snapshot_id,advisory_revision_id,"
            "payload,data_layer,data_sources) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (
                assessment_id,
                case["investigation_id"],
                snapshot.id,
                revision_id,
                Jsonb(assessment.model_dump(mode="json")),
                data.mode,
                Jsonb(list(data.sources)),
            ),
        )
        report = {
            "data_layer": data.mode,
            "data_sources": data.sources,
            "snapshot_id": snapshot_id,
            "revision_id": revision_id,
            "assessment_id": str(assessment_id),
            "exposure": assessment.exposure,
            "sponsor_data_layer_verified": data.mode == "zetaris" and bool(data.sources),
        }
    destination = ROOT / "artifacts" / "zetaris" / "e2e.json"
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not report["sponsor_data_layer_verified"]:
        raise SystemExit("Zetaris did not identify data sources on the investigation read")
    print(f"Zetaris investigation read passed. Evidence: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
