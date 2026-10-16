DROP INDEX IF EXISTS idx_api_tokens_agent;
ALTER TABLE api_tokens DROP COLUMN IF EXISTS agent_id;
