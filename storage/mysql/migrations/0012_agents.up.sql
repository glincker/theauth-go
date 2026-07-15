-- 0012: agents and agent_credentials.
-- scope_grant stored as JSON (Postgres text[] equivalent).
-- Partial index WHERE revoked_at IS NULL becomes a regular index here; the
-- partial filter is enforced in application queries.

CREATE TABLE IF NOT EXISTS agents (
    id              BINARY(16) PRIMARY KEY,
    owner_user_id   BINARY(16),
    organization_id BINARY(16),
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT (''),
    status          VARCHAR(16) NOT NULL DEFAULT 'active',
    client_id       VARCHAR(255) NOT NULL,
    scope_grant     JSON NOT NULL,
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_active_at  DATETIME(6),
    UNIQUE KEY uq_agents_client_id (client_id),
    KEY idx_agents_owner_user (owner_user_id),
    KEY idx_agents_organization (organization_id),
    KEY idx_agents_status (status),
    CONSTRAINT fk_agents_user FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_agents_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    CONSTRAINT fk_agents_client FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE RESTRICT,
    CONSTRAINT chk_agents_status CHECK (status IN ('active', 'suspended', 'revoked'))
);

CREATE TABLE IF NOT EXISTS agent_credentials (
    id           BINARY(16) PRIMARY KEY,
    agent_id     BINARY(16) NOT NULL,
    kind         VARCHAR(16) NOT NULL,
    value_enc    BLOB NOT NULL,
    created_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at   DATETIME(6),
    last_used_at DATETIME(6),
    revoked_at   DATETIME(6),
    KEY idx_agent_credentials_agent (agent_id),
    CONSTRAINT fk_agent_credentials_agent FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    CONSTRAINT chk_agent_credentials_kind CHECK (kind IN ('secret', 'x509', 'jwk'))
);

-- FK from oauth_clients to agents must be added after agents exists.
ALTER TABLE oauth_clients
    ADD CONSTRAINT fk_oauth_clients_agent FOREIGN KEY (owner_agent_id) REFERENCES agents(id) ON DELETE CASCADE;
