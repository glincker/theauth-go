ALTER TABLE api_tokens ADD COLUMN agent_id uuid;
CREATE INDEX idx_api_tokens_agent ON api_tokens (agent_id) WHERE agent_id IS NOT NULL;
