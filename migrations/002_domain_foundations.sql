-- Domain foundations only. Routes and workers for these entities are not implemented yet.
CREATE TABLE inventory_snapshots (
    id UUID PRIMARY KEY,
    application_id UUID NOT NULL REFERENCES applications(id),
    commit_ref TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    completeness TEXT NOT NULL CHECK (completeness IN ('complete', 'partial', 'failed')),
    artifact_path TEXT,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX inventory_application_idx ON inventory_snapshots(application_id, observed_at DESC);

CREATE TABLE components (
    id UUID PRIMARY KEY,
    snapshot_id UUID NOT NULL REFERENCES inventory_snapshots(id),
    name TEXT NOT NULL,
    ecosystem TEXT NOT NULL DEFAULT 'npm',
    resolved_version TEXT,
    direct BOOLEAN NOT NULL,
    dependency_paths JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(dependency_paths) = 'array'),
    metadata JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX components_lookup_idx ON components(ecosystem, name, resolved_version);
CREATE INDEX components_snapshot_idx ON components(snapshot_id);

CREATE TABLE deployments (
    id UUID PRIMARY KEY,
    application_id UUID NOT NULL REFERENCES applications(id),
    snapshot_id UUID REFERENCES inventory_snapshots(id),
    environment TEXT NOT NULL,
    artifact_ref TEXT NOT NULL,
    source_reference TEXT NOT NULL,
    deployed_at TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ,
    CHECK (retired_at IS NULL OR retired_at >= deployed_at)
);

CREATE INDEX deployments_application_idx ON deployments(application_id, deployed_at DESC);

CREATE TABLE advisories (
    id UUID PRIMARY KEY,
    source TEXT NOT NULL,
    source_identifier TEXT NOT NULL,
    aliases JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(aliases) = 'array'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source, source_identifier)
);

CREATE TABLE advisory_revisions (
    id UUID PRIMARY KEY,
    advisory_id UUID NOT NULL REFERENCES advisories(id),
    content_hash TEXT NOT NULL,
    payload JSONB NOT NULL,
    published_at TIMESTAMPTZ,
    retrieved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (advisory_id, content_hash)
);

CREATE TABLE evidence (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    advisory_revision_id UUID REFERENCES advisory_revisions(id),
    source_url TEXT NOT NULL,
    content_hash TEXT,
    excerpt TEXT,
    confidence TEXT NOT NULL CHECK (
        confidence IN ('confirmed', 'preliminary', 'contradictory', 'insufficient')
    ),
    retrieved_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX evidence_investigation_idx ON evidence(investigation_id);

CREATE TABLE findings (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    component_id UUID NOT NULL REFERENCES components(id),
    advisory_revision_id UUID NOT NULL REFERENCES advisory_revisions(id),
    exposure TEXT NOT NULL CHECK (
        exposure IN ('undetermined', 'not_affected', 'potential', 'confirmed')
    ),
    compromise TEXT NOT NULL DEFAULT 'unknown' CHECK (
        compromise IN ('unknown', 'suspected', 'confirmed', 'ruled_out')
    ),
    policy_version TEXT NOT NULL,
    priority TEXT,
    conditions JSONB NOT NULL DEFAULT '{}',
    justification TEXT NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX findings_investigation_idx ON findings(investigation_id);

CREATE TABLE remediation_plans (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    strategy TEXT NOT NULL CHECK (
        strategy IN ('upgrade', 'rollback', 'configuration', 'mitigation', 'abstain')
    ),
    justification TEXT NOT NULL,
    alternatives JSONB NOT NULL DEFAULT '[]',
    validation_plan TEXT NOT NULL,
    rollback_plan TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE patches (
    id UUID PRIMARY KEY,
    plan_id UUID NOT NULL REFERENCES remediation_plans(id),
    base_commit TEXT NOT NULL,
    proposed_commit TEXT NOT NULL,
    branch TEXT NOT NULL,
    diff_hash TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    pull_request_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE validation_runs (
    id UUID PRIMARY KEY,
    patch_id UUID NOT NULL REFERENCES patches(id),
    evaluated_commit TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    command JSONB NOT NULL CHECK (jsonb_typeof(command) = 'array'),
    status TEXT NOT NULL CHECK (status IN ('passed', 'failed', 'incomplete', 'not_run')),
    exit_code INTEGER,
    artifact_path TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    CHECK (finished_at IS NULL OR finished_at >= started_at)
);

CREATE TABLE approvals (
    id UUID PRIMARY KEY,
    patch_id UUID NOT NULL REFERENCES patches(id),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    justification TEXT NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    invalidated_at TIMESTAMPTZ
);

CREATE TABLE workflow_runs (
    id UUID PRIMARY KEY,
    investigation_id UUID NOT NULL REFERENCES investigations(id),
    status TEXT NOT NULL,
    stage TEXT NOT NULL,
    state JSONB NOT NULL DEFAULT '{}',
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
    max_active_seconds INTEGER NOT NULL DEFAULT 1800 CHECK (max_active_seconds > 0),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX workflow_investigation_idx ON workflow_runs(investigation_id, started_at DESC);

-- workflow_runs is a domain record, not a LangGraph checkpoint implementation.

