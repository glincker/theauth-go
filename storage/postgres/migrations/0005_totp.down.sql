ALTER TABLE sessions DROP COLUMN IF EXISTS auth_level;
DROP TABLE IF EXISTS totp_recovery_codes;
DROP TABLE IF EXISTS totp_secrets;
