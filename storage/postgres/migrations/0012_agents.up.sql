-- 0012: agents and agent_credentials (v2.0 phase 3).
--
-- An agent is a first class identity owned by exactly one of a user
-- (personal agent) or an organization (service account). The agent's
-- client_id mirrors a row in oauth_clients (owner_kind = 'agent') so
-- client authentication paths converge on a single table.
--
-- agent_credentials carries one row per secret material, allowing rotation
-- without downtime. kind = 'secret' stores an Argon2id PHC hash of the
-- shared secret; kind = 'x509' and 'jwk' are reserved for later phases
-- (the service layer returns ErrNotImplemented for those kinds in phase 3).

CREATE TABLE agents (
    id              uuid PRIMARY KEY,
    owner_user_id   uuid REFERENCES users(id) ON DELETE CASCADE,
    organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    status          text NOT NULL DEFAULT 'active',
    client_id       text NOT NULL UNIQUE REFERENCES oauth_clients(client_id) ON DELETE RESTRICT,
    scope_grant     text[] NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_active_at  timestamptz,
    CHECK (
        (owner_user_id IS NOT NULL AND organization_id IS NULL) OR
        (owner_user_id IS NULL     AND organization_id IS NOT NULL)
    ),
    CHECK (status IN ('active','suspended','revoked'))
);
CREATE INDEX idx_agents_owner_user        ON agents(owner_user_id);
CREATE INDEX idx_agents_organization      ON agents(organization_id);
CREATE INDEX idx_agents_status            ON agents(status);

CREATE TABLE agent_credentials (
    id           uuid PRIMARY KEY,
    agent_id     uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('secret','x509','jwk')),
    value_enc    bytea NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz
);
CREATE INDEX idx_agent_credentials_agent ON agent_credentials(agent_id);
CREATE INDEX idx_agent_credentials_live  ON agent_credentials(agent_id) WHERE revoked_at IS NULL;
