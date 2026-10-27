CREATE TABLE product_jobs (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    request_key UUID NOT NULL,
    actor TEXT NOT NULL,
    input JSONB NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('running','passed','failed','blocked','cancelled')),
    payload JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(investigation_id, request_key)
);
CREATE TABLE product_approvals (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES product_jobs(id),
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE product_publications (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES product_jobs(id),
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
DO $$ BEGIN
 IF EXISTS (SELECT FROM pg_roles WHERE rolname='warden_app') THEN
   GRANT SELECT, INSERT ON product_jobs, product_approvals, product_publications TO warden_app;
   GRANT UPDATE(status,payload,updated_at) ON product_jobs TO warden_app;
 END IF;
END $$;
