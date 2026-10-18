-- 0033: delegation grant uniqueness only constrains live rows. The original
-- UNIQUE (user_id, agent_id, resource) also blocked re-granting after a revoke.
-- Mirrors sqlite 0031 (partial unique index on live rows) and the memory store.
ALTER TABLE delegation_grants
    DROP CONSTRAINT IF EXISTS delegation_grants_user_id_agent_id_resource_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_delegation_grants_live
    ON delegation_grants (user_id, agent_id, resource) WHERE revoked_at IS NULL;
