-- 0035: optional agent expiry in unix microseconds. NULL means the agent never expires. Past
-- the timestamp the agent is treated as inactive (agent_expired). No backfill needed.
ALTER TABLE theauth_agents ADD COLUMN expires_at INTEGER;
