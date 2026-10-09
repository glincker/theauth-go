-- 0021: per-client access token policy, RFC 9396 authorization_details and
-- opaque (reference) access tokens.
ALTER TABLE oauth_clients
    ADD COLUMN access_token_format            text   NOT NULL DEFAULT '',
    ADD COLUMN access_token_signed_response_alg text NOT NULL DEFAULT '',
    ADD COLUMN authorization_details_types    text[] NOT NULL DEFAULT '{}';

ALTER TABLE oauth_authorization_codes ADD COLUMN authorization_details bytea;
ALTER TABLE oauth_refresh_tokens      ADD COLUMN authorization_details bytea;

-- Only the SHA-256 hash of an opaque token is stored. claims holds the JSON
-- claim set a JWT would have carried so introspection answers the same way.
CREATE TABLE oauth_opaque_access_tokens (
    hash       bytea PRIMARY KEY,
    jti        text NOT NULL,
    client_id  text NOT NULL,
    claims     bytea NOT NULL,
    issued_at  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX idx_oauth_opaque_access_tokens_expires ON oauth_opaque_access_tokens(expires_at);
