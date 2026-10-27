"""Explicit local mode or mandatory Zetaris reads. No fallback between the two."""

import json
import re
import time
from uuid import UUID

from alaira_warden.integration import convert
from alaira_warden.providers import ZetarisClient
from alaira_warden.providers.errors import ProviderError


class CaseData:
    def __init__(self, settings, deadline, client=None):
        self.mode = settings.warden_data_mode
        self.settings = settings
        self.deadline = deadline
        self.sources = []
        self.client = client or ZetarisClient(
            base_url=settings.warden_zetaris_base_url,
            org_id=settings.warden_zetaris_org_id,
            api_key=settings.warden_zetaris_api_key.get_secret_value(),
            username=settings.warden_zetaris_username,
            password=settings.warden_zetaris_password.get_secret_value(),
        )

    def _query(self, table, predicate):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,3}", table):
            raise ProviderError(
                provider="zetaris",
                kind="unconfigured",
                reason="Configure the registered data views",
            )
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderError(
                provider="zetaris", kind="timeout", reason="Stage deadline exceeded"
            )
        result = self.client.query(
            f"SELECT payload FROM {table} WHERE {predicate} LIMIT 1", timeout=min(remaining, 20)
        )
        if [column.lower() for column in result.columns] != ["payload"] or len(result.rows) != 1:
            raise ProviderError(
                provider="zetaris", kind="invalid_response", reason="Expected one data view row"
            )
        self.sources.extend(source for source in result.sources if source not in self.sources)
        try:
            payload = json.loads(result.rows[0][0])
        except (ValueError, TypeError):
            raise ProviderError(
                provider="zetaris", kind="invalid_response", reason="Invalid data view payload"
            ) from None
        if not isinstance(payload, dict):
            raise ProviderError(
                provider="zetaris", kind="invalid_response", reason="Invalid data view object"
            )
        return payload

    def snapshot(self, connection, snapshot_id, application_id):
        snapshot_id, application_id = UUID(str(snapshot_id)), UUID(str(application_id))
        if self.mode == "zetaris":
            data = self._query(
                self.settings.warden_zetaris_inventory_table,
                f"id = '{snapshot_id}' AND application_id = '{application_id}'",
            )
            row, components = data["snapshot"], data["components"]
            if (
                UUID(str(row["id"])) != snapshot_id
                or UUID(str(row["application_id"])) != application_id
            ):
                raise ValueError("Zetaris snapshot scope mismatch")
            local, local_components = self._local_snapshot(connection, snapshot_id, application_id)
            remote_snapshot = convert.snapshot(
                row, sorted(components, key=lambda item: str(item["id"]))
            )
            expected = convert.snapshot(local, local_components)
            if remote_snapshot != expected:
                raise ValueError("Zetaris inventory differs from the pinned snapshot")
            return row, components
        return self._local_snapshot(connection, snapshot_id, application_id)

    @staticmethod
    def _local_snapshot(connection, snapshot_id, application_id):
        row = connection.execute(
            "SELECT * FROM inventory_snapshots WHERE id=%s AND application_id=%s",
            (snapshot_id, application_id),
        ).fetchone()
        components = connection.execute(
            "SELECT * FROM components WHERE snapshot_id=%s ORDER BY id", (snapshot_id,)
        ).fetchall()
        return row, components

    def advisory(self, connection, revision, case_id):
        revision, case_id = UUID(str(revision)), UUID(str(case_id))
        # Validate membership locally before querying any external layer.
        record = connection.execute(
            "SELECT r.payload FROM advisory_revisions r JOIN evidence e "
            "ON e.advisory_revision_id=r.id WHERE r.id=%s AND e.investigation_id=%s LIMIT 1",
            (revision, case_id),
        ).fetchone()
        if not record:
            raise ValueError("Advisory revision outside the case")
        if self.mode == "zetaris":
            payload = self._query(
                self.settings.warden_zetaris_evidence_table,
                f"revision_id = '{revision}' AND investigation_id = '{case_id}'",
            )
            # The data layer may not substitute a newer/different origin revision.
            if payload != record["payload"]:
                raise ValueError("Zetaris advisory revision mismatch")
            return payload
        return record["payload"]
