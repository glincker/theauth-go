-- Reverse of 0012_agents.up.sql. agent_credentials cascades from agents.
DROP INDEX IF EXISTS idx_agent_credentials_live;
DROP INDEX IF EXISTS idx_agent_credentials_agent;
DROP TABLE IF EXISTS agent_credentials;

DROP INDEX IF EXISTS idx_agents_status;
DROP INDEX IF EXISTS idx_agents_organization;
DROP INDEX IF EXISTS idx_agents_owner_user;
DROP TABLE IF EXISTS agents;
