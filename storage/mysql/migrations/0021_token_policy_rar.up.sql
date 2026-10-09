-- 0021: per-client access token policy, RFC 9396 authorization_details and
-- opaque (reference) access tokens.
ALTER TABLE oauth_clients
    ADD COLUMN access_token_format              VARCHAR(16)  NOT NULL DEFAULT '',
    ADD COLUMN access_token_signed_response_alg VARCHAR(16)  NOT NULL DEFAULT '',
    ADD COLUMN authorization_details_types      TEXT         NOT NULL DEFAULT ('[]');

ALTER TABLE oauth_authorization_codes ADD COLUMN authorization_details BLOB NULL;
ALTER TABLE oauth_refresh_tokens      ADD COLUMN authorization_details BLOB NULL;

-- Only the SHA-256 hash of an opaque token is stored. claims holds the JSON
-- claim set a JWT would have carried so introspection answers the same way.
CREATE TABLE IF NOT EXISTS oauth_opaque_access_tokens (
    hash       VARBINARY(64) PRIMARY KEY,
    jti        VARCHAR(255) NOT NULL,
    client_id  VARCHAR(512) NOT NULL,
    claims     BLOB NOT NULL,
    issued_at  DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    KEY idx_oauth_opaque_access_tokens_expires (expires_at)
);
