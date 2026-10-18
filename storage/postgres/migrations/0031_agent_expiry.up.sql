-- 0031: optional agent expiry. A NULL expires_at means the agent never expires. Past the
-- timestamp the agent is treated as inactive (agent_expired). No backfill needed.
ALTER TABLE agents ADD COLUMN expires_at timestamptz;
