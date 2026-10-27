CREATE TABLE model_proposals (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    actor TEXT NOT NULL,
    input_digest TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE assessments ADD COLUMN data_layer TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN data_sources JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN review_id UUID REFERENCES evidence_reviews(id);
-- Register these limited views in Zetaris; never give it an identity/admin SQL login.
CREATE VIEW warden_inventory_data AS
SELECT s.id, s.application_id,
    jsonb_build_object('snapshot',to_jsonb(s),'components',
        COALESCE((SELECT jsonb_agg(to_jsonb(c)) FROM components c WHERE c.snapshot_id=s.id),'[]'))::text AS payload
FROM inventory_snapshots s;
CREATE VIEW warden_evidence_data AS
SELECT DISTINCT e.investigation_id,r.id AS revision_id,r.payload::text AS payload
FROM evidence e JOIN advisory_revisions r ON r.id=e.advisory_revision_id;
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='warden_data_reader') THEN
        CREATE ROLE warden_data_reader NOLOGIN;
    END IF;
    GRANT USAGE ON SCHEMA public TO warden_data_reader;
    GRANT SELECT ON warden_inventory_data,warden_evidence_data TO warden_data_reader;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname='warden_app') THEN
        GRANT SELECT, INSERT ON model_proposals TO warden_app;
        GRANT SELECT ON warden_inventory_data,warden_evidence_data TO warden_app;
    END IF;
END $$;
