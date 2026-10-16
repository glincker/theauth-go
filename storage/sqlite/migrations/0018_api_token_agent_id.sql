ALTER TABLE theauth_api_tokens ADD COLUMN agent_id TEXT;
CREATE INDEX idx_theauth_api_tokens_agent ON theauth_api_tokens (agent_id) WHERE agent_id IS NOT NULL;
