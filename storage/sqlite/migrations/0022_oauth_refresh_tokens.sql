-- 0022: rotating OAuth refresh tokens. family_id links a rotation chain so a
-- replayed token can revoke the whole family. auth_code_hash ties a family to
-- the authorization code it was first issued from (code replay revokes it),
-- dpop_jkt holds the sender constraint, and the remaining columns carry RFC
-- 9396 authorization_details and the authentication context unchanged through
-- the chain.
CREATE TABLE IF NOT EXISTS theauth_oauth_refresh_tokens (
    id                    TEXT PRIMARY KEY,
    hash                  BLOB NOT NULL,
    family_id             TEXT NOT NULL,
    client_id             TEXT NOT NULL,
    user_id               TEXT,
    agent_id              TEXT,
    scope                 TEXT NOT NULL DEFAULT '[]',
    resource              TEXT NOT NULL,
    parent_jti            TEXT NOT NULL DEFAULT '',
    issued_at             INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    revoked_at            INTEGER,
    revocation_note       TEXT NOT NULL DEFAULT '',
    dpop_jkt              TEXT NOT NULL DEFAULT '',
    auth_code_hash        TEXT NOT NULL DEFAULT '',
    authorization_details BLOB,
    auth_time             INTEGER,
    acr                   TEXT NOT NULL DEFAULT '',
    amr                   TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_oauth_refresh_tokens_hash_uq ON theauth_oauth_refresh_tokens (hash);
CREATE INDEX IF NOT EXISTS theauth_oauth_refresh_tokens_family_idx ON theauth_oauth_refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS theauth_oauth_refresh_tokens_user_idx ON theauth_oauth_refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS theauth_oauth_refresh_tokens_agent_idx ON theauth_oauth_refresh_tokens (agent_id);
CREATE INDEX IF NOT EXISTS theauth_oauth_refresh_tokens_client_idx ON theauth_oauth_refresh_tokens (client_id);
CREATE INDEX IF NOT EXISTS theauth_oauth_refresh_tokens_auth_code_idx ON theauth_oauth_refresh_tokens (auth_code_hash) WHERE auth_code_hash <> '';
