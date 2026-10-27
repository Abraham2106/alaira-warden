ALTER TABLE investigations DROP CONSTRAINT investigations_status_check;
ALTER TABLE investigations ADD CONSTRAINT investigations_status_check
    CHECK(status IN (
        'detected','investigating','awaiting_review','requires_intervention',
        'closed','cancelled'
    ));
CREATE TABLE agent_events (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    run_id UUID REFERENCES workflow_runs(id),
    agent TEXT NOT NULL CHECK (char_length(agent) BETWEEN 1 AND 40),
    stage TEXT NOT NULL CHECK (char_length(stage) BETWEEN 1 AND 40),
    status TEXT NOT NULL CHECK (status IN (
        'started','decided','handed_off','failed','skipped','blocked'
    )),
    summary TEXT NOT NULL CHECK (char_length(trim(summary)) BETWEEN 1 AND 400),
    detail JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX agent_events_case_idx ON agent_events (investigation_id, created_at);
CREATE TABLE investigation_plans (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    actor TEXT NOT NULL,
    payload JSONB NOT NULL,
    content_hash TEXT NOT NULL CHECK (content_hash ~ '^[a-f0-9]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE investigation_patches (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    plan_id UUID NOT NULL REFERENCES investigation_plans(id),
    actor TEXT NOT NULL,
    payload JSONB NOT NULL,
    content_hash TEXT NOT NULL CHECK (content_hash ~ '^[a-f0-9]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE investigation_validations (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    patch_id UUID NOT NULL REFERENCES investigation_patches(id),
    actor TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE investigation_approvals (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('plan','patch')),
    artifact_id UUID NOT NULL,
    artifact_hash TEXT NOT NULL CHECK (artifact_hash ~ '^[a-f0-9]{64}$'),
    decision TEXT NOT NULL CHECK (decision IN ('approved','rejected')),
    actor TEXT NOT NULL,
    justification TEXT NOT NULL CHECK (char_length(trim(justification)) BETWEEN 10 AND 2000),
    valid BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE investigation_closures (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    outcome TEXT NOT NULL CHECK (outcome IN (
        'not_affected','discarded','risk_accepted','cancelled'
    )),
    actor TEXT NOT NULL,
    justification TEXT NOT NULL CHECK (char_length(trim(justification)) BETWEEN 10 AND 2000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname='warden_app') THEN
        GRANT SELECT, INSERT ON agent_events, investigation_plans, investigation_patches,
            investigation_validations, investigation_approvals, investigation_closures
            TO warden_app;
        GRANT UPDATE (valid) ON investigation_approvals TO warden_app;
        GRANT UPDATE (status, exposure) ON investigations TO warden_app;
    END IF;
END $$;
