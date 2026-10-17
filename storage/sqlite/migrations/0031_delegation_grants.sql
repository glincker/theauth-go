-- 0031: delegation grants (port of postgres 0013). One live grant per
-- (user, agent, resource); a revoked grant frees the tuple so a fresh grant
-- can replace it (matches the memory adapter and the shared contract suite).
-- Times are Unix microseconds, scope_grant is a JSON array. No foreign keys.
CREATE TABLE IF NOT EXISTS theauth_delegation_grants (
    id                   TEXT PRIMARY KEY,
    user_id              TEXT NOT NULL,
    agent_id             TEXT NOT NULL,
    organization_id      TEXT,
    scope_grant          TEXT NOT NULL DEFAULT '[]',
    resource             TEXT NOT NULL,
    max_duration_seconds INTEGER NOT NULL,
    created_at           INTEGER NOT NULL,
    expires_at           INTEGER,
    revoked_at           INTEGER,
    revocation_note      TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_theauth_delegation_grants_live
    ON theauth_delegation_grants (user_id, agent_id, resource) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_theauth_delegation_grants_user ON theauth_delegation_grants (user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_theauth_delegation_grants_agent ON theauth_delegation_grants (agent_id, created_at);
