-- 0019: sender-constrained refresh tokens, replay revocation, access-token
-- denylist. Authorization codes are now stored as SHA-256 hashes; any code
-- still held in plaintext (60 second TTL) is dropped so no plaintext
-- credential survives the upgrade.
DELETE FROM oauth_authorization_codes;

ALTER TABLE oauth_refresh_tokens
    ADD COLUMN dpop_jkt       text NOT NULL DEFAULT '',
    ADD COLUMN auth_code_hash text NOT NULL DEFAULT '';
CREATE INDEX idx_oauth_refresh_tokens_auth_code ON oauth_refresh_tokens(auth_code_hash) WHERE auth_code_hash <> '';

CREATE TABLE oauth_revoked_jtis (
    jti        text PRIMARY KEY,
    expires_at timestamptz NOT NULL
);
CREATE INDEX idx_oauth_revoked_jtis_expires ON oauth_revoked_jtis(expires_at);
