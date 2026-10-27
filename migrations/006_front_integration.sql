ALTER TABLE applications ADD COLUMN owner TEXT,
    ADD COLUMN criticality TEXT CHECK (criticality IN ('low','medium','high','critical')),
    ADD COLUMN organization TEXT,
    ADD COLUMN environments JSONB NOT NULL DEFAULT '[]'
        CHECK (jsonb_typeof(environments) = 'array');
ALTER TABLE inventory_snapshots ADD COLUMN warnings JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN artifact_hash TEXT,
    ADD COLUMN metadata JSONB NOT NULL DEFAULT '{}';
ALTER TABLE deployments ADD COLUMN commit_sha TEXT,
    ADD CONSTRAINT deployment_provenance CHECK (snapshot_id IS NOT NULL OR commit_sha IS NOT NULL);
-- Scope must also hold below the API/handler layer.
ALTER TABLE inventory_snapshots ADD UNIQUE(id, application_id);
ALTER TABLE deployments ADD CONSTRAINT deployment_snapshot_scope
    FOREIGN KEY(snapshot_id, application_id) REFERENCES inventory_snapshots(id, application_id);
CREATE TABLE workflow_stage_results (
    run_id UUID NOT NULL REFERENCES workflow_runs(id),
    stage TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(run_id, stage)
);
CREATE TABLE assessments (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    snapshot_id UUID NOT NULL REFERENCES inventory_snapshots(id),
    advisory_revision_id UUID NOT NULL REFERENCES advisory_revisions(id),
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE evidence_reviews (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    advisory_revision_id UUID NOT NULL REFERENCES advisory_revisions(id),
    confidence TEXT NOT NULL CHECK(confidence IN ('confirmed','preliminary','contradictory','insufficient')),
    actor TEXT NOT NULL,
    justification TEXT NOT NULL CHECK(length(trim(justification)) BETWEEN 10 AND 2000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE integration_checks (
    id UUID PRIMARY KEY,
    adapter TEXT NOT NULL,
    operation TEXT NOT NULL,
    payload JSONB NOT NULL,
    actor TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE investigations DROP CONSTRAINT investigations_exposure_check;
ALTER TABLE investigations ADD CONSTRAINT investigations_exposure_check
    CHECK(exposure IN ('undetermined','not_affected','potential','confirmed'));
ALTER TABLE investigations DROP CONSTRAINT investigations_status_check;
ALTER TABLE investigations ADD CONSTRAINT investigations_status_check
    CHECK(status IN ('detected','requires_intervention','investigating','awaiting_review'));
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname='warden_app') THEN
        GRANT SELECT, INSERT ON workflow_stage_results, assessments, evidence_reviews,
            integration_checks TO warden_app;
        REVOKE UPDATE, DELETE, TRUNCATE ON inventory_snapshots, components FROM warden_app;
        REVOKE UPDATE, DELETE, TRUNCATE ON deployments FROM warden_app;
        GRANT UPDATE(retired_at) ON deployments TO warden_app;
        REVOKE UPDATE, DELETE, TRUNCATE ON advisory_revisions, findings, evidence FROM warden_app;
    END IF;
END $$;
