CREATE TABLE IF NOT EXISTS theauth_oauth_accounts (
    id                TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL REFERENCES theauth_users (id) ON DELETE CASCADE,
    provider          TEXT NOT NULL,
    provider_user_id  TEXT NOT NULL,
    access_token_enc  BLOB NOT NULL,
    refresh_token_enc BLOB,
    expires_at        INTEGER,
    scope             TEXT NOT NULL DEFAULT '',
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_oauth_accounts_provider_uq ON theauth_oauth_accounts (provider, provider_user_id);
CREATE INDEX IF NOT EXISTS theauth_oauth_accounts_user_idx ON theauth_oauth_accounts (user_id);
