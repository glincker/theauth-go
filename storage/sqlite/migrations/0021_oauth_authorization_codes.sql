-- 0021: single use OAuth authorization codes. The code column holds whatever
-- key the server derives (a SHA-256 hash), never a plaintext credential. The
-- consume step is a DELETE ... RETURNING, so exactly one caller wins. Carries
-- the RFC 9396 authorization_details document and the authentication context
-- (auth_time as Unix microseconds with NULL meaning none, acr, and amr as a
-- space separated list). No foreign keys: the 0029 triggers remove codes when
-- their client, user or organization is deleted.
CREATE TABLE IF NOT EXISTS theauth_oauth_authorization_codes (
    code                  TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    user_id               TEXT NOT NULL,
    organization_id       TEXT,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT NOT NULL DEFAULT '[]',
    resource              TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    nonce                 TEXT NOT NULL DEFAULT '',
    expires_at            INTEGER NOT NULL,
    created_at            INTEGER NOT NULL,
    authorization_details BLOB,
    auth_time             INTEGER,
    acr                   TEXT NOT NULL DEFAULT '',
    amr                   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS theauth_oauth_authorization_codes_expires_idx ON theauth_oauth_authorization_codes (expires_at);
CREATE INDEX IF NOT EXISTS theauth_oauth_authorization_codes_client_idx ON theauth_oauth_authorization_codes (client_id);
CREATE INDEX IF NOT EXISTS theauth_oauth_authorization_codes_user_idx ON theauth_oauth_authorization_codes (user_id);
