DROP INDEX IF EXISTS idx_delegation_grants_live;

-- Restoring the full constraint fails if a revoked and a live grant share a tuple.
ALTER TABLE delegation_grants
    ADD CONSTRAINT delegation_grants_user_id_agent_id_resource_key UNIQUE (user_id, agent_id, resource);
