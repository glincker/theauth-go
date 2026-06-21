-- 0010: audit log (v1.0)
--
-- Append-only. No UPDATE, no DELETE. Indexes are tuned for the read API in
-- handlers_audit.go: org scope + reverse chronology, actor lookup, action
-- lookup. metadata is jsonb so we can later add GIN indexes per consumer
-- without a schema migration.

CREATE TABLE audit_events (
    id                uuid PRIMARY KEY,
    organization_id   uuid REFERENCES organizations(id) ON DELETE SET NULL,
    actor_user_id     uuid REFERENCES users(id) ON DELETE SET NULL,
    actor_session_id  uuid REFERENCES sessions(id) ON DELETE SET NULL,
    action            text NOT NULL,
    target_type       text,
    target_id         text,
    metadata          jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip                inet,
    user_agent        text,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_org_created_at        ON audit_events (organization_id, created_at DESC);
CREATE INDEX idx_audit_actor_created_at      ON audit_events (actor_user_id, created_at DESC);
CREATE INDEX idx_audit_action_created_at     ON audit_events (action, created_at DESC);

-- Defense in depth: revoke UPDATE / DELETE at the role level if the consumer
-- creates a dedicated app role. Documented in STABILITY.md; not enforced in
-- migration because consumers manage roles themselves.
