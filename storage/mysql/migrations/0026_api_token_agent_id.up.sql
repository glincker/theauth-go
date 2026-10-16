ALTER TABLE api_tokens ADD COLUMN agent_id BINARY(16) NULL, ADD KEY idx_api_tokens_agent (agent_id);
