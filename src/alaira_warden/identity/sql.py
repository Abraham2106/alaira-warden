"""Proposed DDL. Importing this module does not connect or execute SQL."""

PROPOSED_IDENTITY_DDL = """\
-- Identity and authorization (WBS 1.2.3). Apply as a new migration after 003.
-- Do not store API credentials in plaintext. token_hash is HMAC-SHA256 (hex).
-- The pepper stays outside PostgreSQL. Importing the identity package does not run this script.

CREATE TABLE identity_subjects (
    id UUID PRIMARY KEY,
    display_name TEXT NOT NULL CHECK (length(trim(display_name)) BETWEEN 1 AND 200),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE identity_assignments (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES identity_subjects (id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (
        role IN ('administrador', 'analista', 'desarrollador', 'aprobador', 'auditor')
    ),
    application_id UUID NULL REFERENCES applications (id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- NULL application_id is an explicit platform-wide assignment, not "any token".
CREATE UNIQUE INDEX identity_assignments_application_uidx
    ON identity_assignments (subject_id, role, application_id)
    WHERE application_id IS NOT NULL;

CREATE UNIQUE INDEX identity_assignments_platform_uidx
    ON identity_assignments (subject_id, role)
    WHERE application_id IS NULL;

CREATE INDEX identity_assignments_subject_idx ON identity_assignments (subject_id);
CREATE INDEX identity_assignments_application_idx ON identity_assignments (application_id);

CREATE TABLE identity_credentials (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES identity_subjects (id) ON DELETE RESTRICT,
    token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    label TEXT NOT NULL CHECK (length(trim(label)) BETWEEN 1 AND 120),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ NULL,
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX identity_credentials_subject_idx ON identity_credentials (subject_id);

REVOKE ALL ON identity_subjects, identity_assignments, identity_credentials FROM PUBLIC;

-- 003 already ran, so new tables need their own grants. Do not grant UPDATE on token_hash.
REVOKE ALL ON identity_subjects, identity_assignments, identity_credentials FROM warden_app;
GRANT SELECT, INSERT ON identity_subjects TO warden_app;
GRANT UPDATE (is_active) ON identity_subjects TO warden_app;
GRANT SELECT, INSERT, DELETE ON identity_assignments TO warden_app;
GRANT SELECT, INSERT ON identity_credentials TO warden_app;
GRANT UPDATE (revoked_at) ON identity_credentials TO warden_app;
"""

# Distinct from the migration advisory lock 817402.
PROVISION_ADVISORY_LOCK = 817403
