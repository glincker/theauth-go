-- 0013: delegation grants.
-- scope_grant stored as JSON. Uniqueness on (user_id, agent_id, resource)
-- enforced via composite unique index.

CREATE TABLE IF NOT EXISTS delegation_grants (
    id                   BINARY(16) PRIMARY KEY,
    user_id              BINARY(16) NOT NULL,
    agent_id             BINARY(16) NOT NULL,
    organization_id      BINARY(16),
    scope_grant          JSON NOT NULL,
    resource             TEXT NOT NULL,
    max_duration_seconds INT NOT NULL,
    created_at           DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at           DATETIME(6),
    revoked_at           DATETIME(6),
    revocation_note      TEXT NOT NULL DEFAULT '',
    KEY idx_delegation_grants_user_id (user_id),
    KEY idx_delegation_grants_agent_id (agent_id),
    KEY idx_delegation_grants_resource (resource(191)),
    CONSTRAINT fk_delegation_grants_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_delegation_grants_agent FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    CONSTRAINT fk_delegation_grants_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- resource is TEXT so we cannot include it directly in a unique index.
-- We enforce (user_id, agent_id, resource) uniqueness at the application
-- layer in InsertDelegationGrant using a SELECT-then-INSERT transaction.

-- Add FK from audit_events to agents (agents table now exists).
ALTER TABLE audit_events
    ADD CONSTRAINT fk_audit_events_agent FOREIGN KEY (actor_agent_id) REFERENCES agents(id) ON DELETE SET NULL;
