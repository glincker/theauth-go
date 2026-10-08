-- 0019: sender-constrained refresh tokens, replay revocation, access-token
-- denylist. Authorization codes are now stored as SHA-256 hashes; any code
-- still held in plaintext (60 second TTL) is dropped.
DELETE FROM oauth_authorization_codes;

ALTER TABLE oauth_refresh_tokens
    ADD COLUMN dpop_jkt       VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN auth_code_hash VARCHAR(255) NOT NULL DEFAULT '',
    ADD KEY idx_oauth_refresh_tokens_auth_code (auth_code_hash);

CREATE TABLE IF NOT EXISTS oauth_revoked_jtis (
    jti        VARCHAR(255) PRIMARY KEY,
    expires_at DATETIME(6) NOT NULL,
    KEY idx_oauth_revoked_jtis_expires (expires_at)
);
