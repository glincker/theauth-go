-- 0030: agent identities and their credentials (port of postgres 0012).
-- Exactly one of owner_user_id / organization_id is set. client_id is unique
-- and mirrors an OAuth client id, but no foreign key is declared so the table
-- does not depend on the OAuth server tables. Ids are ULID text, times are
-- Unix microseconds, scope_grant is a JSON array. No foreign keys to users or
-- organizations: agent ids may belong to external registries and the shared
-- contract suites insert owners that have no row.
CREATE TABLE IF NOT EXISTS theauth_agents (
    id              TEXT PRIMARY KEY,
    owner_user_id   TEXT,
    organization_id TEXT,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
    client_id       TEXT NOT NULL UNIQUE,
    scope_grant     TEXT NOT NULL DEFAULT '[]',
    created_at      INTEGER NOT NULL,
    last_active_at  INTEGER,
    CHECK (
        (owner_user_id IS NOT NULL AND organization_id IS NULL) OR
        (owner_user_id IS NULL     AND organization_id IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_theauth_agents_owner_user ON theauth_agents (owner_user_id) WHERE owner_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_theauth_agents_organization ON theauth_agents (organization_id) WHERE organization_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_theauth_agents_status ON theauth_agents (status);

CREATE TABLE IF NOT EXISTS theauth_agent_credentials (
    id           TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('secret','x509','jwk')),
    value_enc    BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    last_used_at INTEGER,
    revoked_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_theauth_agent_credentials_agent ON theauth_agent_credentials (agent_id, created_at);
