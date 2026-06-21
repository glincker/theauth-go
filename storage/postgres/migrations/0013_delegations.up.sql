-- 0013: delegation grants and audit chain column (v2.0 phase 4).
--
-- One row per (user, agent, resource) tuple that the user has approved.
-- Token exchange (RFC 8693) consults this row at every mint; revocation
-- flips revoked_at and an introspection check on every resource request
-- propagates the change inside IntrospectionCacheTTL (default 60s).
--
-- scope_grant caps the scopes a token exchange call may request for the
-- (user, agent, resource) triple. max_duration_seconds caps the exp on any
-- minted access token; the AS takes the strict min of this and its own
-- AccessTokenTTL.

CREATE TABLE delegation_grants (
    id                   uuid PRIMARY KEY,
    user_id              uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    agent_id             uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    organization_id      uuid REFERENCES organizations(id) ON DELETE CASCADE,
    scope_grant          text[] NOT NULL,
    resource             text NOT NULL,
    max_duration_seconds integer NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz,
    revoked_at           timestamptz,
    revocation_note      text NOT NULL DEFAULT '',
    UNIQUE (user_id, agent_id, resource)
);
CREATE INDEX idx_delegation_grants_user_id  ON delegation_grants(user_id);
CREATE INDEX idx_delegation_grants_agent_id ON delegation_grants(agent_id);
CREATE INDEX idx_delegation_grants_resource ON delegation_grants(resource);

-- Audit log extension (v1.0 already created audit_events; we add the actor
-- agent column so chained operations can record which agent acted on whose
-- behalf without parsing the JWT payload).
ALTER TABLE audit_events ADD COLUMN actor_agent_id uuid REFERENCES agents(id) ON DELETE SET NULL;
CREATE INDEX idx_audit_events_actor_agent_id ON audit_events(actor_agent_id);
