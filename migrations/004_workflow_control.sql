-- Durable control ledger. LangGraph checkpoints live in a separate, owner-created schema.
ALTER TABLE workflow_runs
    ADD COLUMN actor TEXT,
    ADD COLUMN request_key UUID,
    ADD COLUMN request_hash TEXT,
    ADD COLUMN pause_requested BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN cancel_requested BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN reserved_ms BIGINT NOT NULL DEFAULT 0 CHECK (reserved_ms >= 0);

CREATE UNIQUE INDEX workflow_request_idx ON workflow_runs(investigation_id, request_key);

