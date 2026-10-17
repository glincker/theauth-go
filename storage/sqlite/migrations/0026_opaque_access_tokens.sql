-- 0026: opaque (reference) access tokens. Only the SHA-256 hash of a token is
-- stored. claims holds the JSON claim set a JWT would have carried so
-- introspection answers the same way for both formats.
CREATE TABLE IF NOT EXISTS theauth_oauth_opaque_access_tokens (
    hash       BLOB PRIMARY KEY,
    jti        TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    claims     BLOB NOT NULL,
    issued_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS theauth_oauth_opaque_access_tokens_expires_idx ON theauth_oauth_opaque_access_tokens (expires_at);
