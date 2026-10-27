CREATE TABLE hmem_engine_state (
    id TEXT PRIMARY KEY CHECK (id = 'default'),
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE hmem_recalls (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    run_id UUID REFERENCES workflow_runs(id),
    query TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX hmem_recalls_case_idx ON hmem_recalls (investigation_id, created_at DESC);
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname='warden_app') THEN
        GRANT SELECT, INSERT, UPDATE ON hmem_engine_state TO warden_app;
        GRANT SELECT, INSERT ON hmem_recalls TO warden_app;
    END IF;
END $$;
