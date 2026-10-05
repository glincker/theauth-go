CREATE TABLE IF NOT EXISTS theauth_audit_events (
    id               TEXT PRIMARY KEY,
    organization_id  TEXT,
    actor_user_id    TEXT,
    actor_session_id TEXT,
    action           TEXT NOT NULL,
    target_type      TEXT NOT NULL DEFAULT '',
    target_id        TEXT NOT NULL DEFAULT '',
    metadata         TEXT NOT NULL DEFAULT '{}',
    ip               TEXT NOT NULL DEFAULT '',
    user_agent       TEXT NOT NULL DEFAULT '',
    created_at       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_audit_org_created_idx ON theauth_audit_events (organization_id, created_at);
CREATE INDEX IF NOT EXISTS theauth_audit_actor_created_idx ON theauth_audit_events (actor_user_id, created_at);
CREATE INDEX IF NOT EXISTS theauth_audit_action_created_idx ON theauth_audit_events (action, created_at);
