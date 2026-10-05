CREATE TABLE IF NOT EXISTS theauth_users (
    id                TEXT PRIMARY KEY,
    email             TEXT NOT NULL COLLATE NOCASE,
    email_verified_at INTEGER,
    name              TEXT NOT NULL DEFAULT '',
    avatar_url        TEXT NOT NULL DEFAULT '',
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    external_id       TEXT NOT NULL DEFAULT '',
    given_name        TEXT NOT NULL DEFAULT '',
    family_name       TEXT NOT NULL DEFAULT '',
    display_name      TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_users_email_uq ON theauth_users (email);

CREATE TABLE IF NOT EXISTS theauth_sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES theauth_users (id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    auth_level TEXT NOT NULL DEFAULT 'full'
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_sessions_token_hash_uq ON theauth_sessions (token_hash);
CREATE INDEX IF NOT EXISTS theauth_sessions_user_id_idx ON theauth_sessions (user_id);
CREATE INDEX IF NOT EXISTS theauth_sessions_expires_at_idx ON theauth_sessions (expires_at);

CREATE TABLE IF NOT EXISTS theauth_magic_links (
    id         TEXT PRIMARY KEY,
    email      TEXT NOT NULL COLLATE NOCASE,
    token_hash BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_magic_links_token_hash_uq ON theauth_magic_links (token_hash);
CREATE INDEX IF NOT EXISTS theauth_magic_links_email_idx ON theauth_magic_links (email);
CREATE INDEX IF NOT EXISTS theauth_magic_links_expires_at_idx ON theauth_magic_links (expires_at);

CREATE TABLE IF NOT EXISTS theauth_user_passwords (
    user_id       TEXT PRIMARY KEY REFERENCES theauth_users (id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_password_reset_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES theauth_users (id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_password_reset_tokens_hash_uq ON theauth_password_reset_tokens (token_hash);
CREATE INDEX IF NOT EXISTS theauth_password_reset_tokens_user_idx ON theauth_password_reset_tokens (user_id);
CREATE INDEX IF NOT EXISTS theauth_password_reset_tokens_expires_idx ON theauth_password_reset_tokens (expires_at);
