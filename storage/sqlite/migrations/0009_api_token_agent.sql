ALTER TABLE theauth_api_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_api_tokens ADD COLUMN agent_name TEXT NOT NULL DEFAULT '';
ALTER TABLE theauth_api_tokens ADD COLUMN delegated_by TEXT;
