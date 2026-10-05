DROP TABLE IF EXISTS throttle_entries;
DROP TABLE IF EXISTS totp_last_steps;
DROP TABLE IF EXISTS device_codes;
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS session_links;
DROP INDEX IF EXISTS idx_sessions_credential_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS credential_id, DROP COLUMN IF EXISTS elevated_until, DROP COLUMN IF EXISTS last_seen_at;
