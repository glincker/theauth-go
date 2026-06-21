-- Reverse of 0013_delegations.up.sql.
DROP INDEX IF EXISTS idx_audit_events_actor_agent_id;
ALTER TABLE audit_events DROP COLUMN IF EXISTS actor_agent_id;

DROP INDEX IF EXISTS idx_delegation_grants_resource;
DROP INDEX IF EXISTS idx_delegation_grants_agent_id;
DROP INDEX IF EXISTS idx_delegation_grants_user_id;
DROP TABLE IF EXISTS delegation_grants;
