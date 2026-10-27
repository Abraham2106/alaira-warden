CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    repository TEXT NOT NULL,
    ecosystem TEXT NOT NULL DEFAULT 'npm' CHECK (ecosystem = 'npm'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS investigations (
    id UUID PRIMARY KEY,
    application_id UUID NOT NULL REFERENCES applications(id),
    title TEXT NOT NULL CHECK (length(trim(title)) > 0),
    source_url TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'detected' CHECK (status IN ('detected', 'requires_intervention')),
    exposure TEXT NOT NULL DEFAULT 'undetermined' CHECK (exposure = 'undetermined'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS investigations_application_idx
    ON investigations(application_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    entity_id UUID NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Application code only inserts audit events. Database-level append-only roles are pending.

