DROP TABLE IF EXISTS oauth_revoked_jtis;
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_auth_code;
ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS auth_code_hash, DROP COLUMN IF EXISTS dpop_jkt;
