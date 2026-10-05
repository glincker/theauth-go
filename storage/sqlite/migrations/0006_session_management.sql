ALTER TABLE theauth_sessions ADD COLUMN last_seen_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE theauth_sessions ADD COLUMN elevated_until INTEGER;
ALTER TABLE theauth_sessions ADD COLUMN credential_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS theauth_sessions_credential_idx ON theauth_sessions (credential_id) WHERE credential_id <> '';

CREATE TABLE IF NOT EXISTS theauth_session_links (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES theauth_users (id) ON DELETE CASCADE,
    token_hash    BLOB NOT NULL,
    credential_id TEXT NOT NULL DEFAULT '',
    session_ttl   INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    consumed_at   INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_session_links_token_hash_uq ON theauth_session_links (token_hash);
CREATE INDEX IF NOT EXISTS theauth_session_links_expires_idx ON theauth_session_links (expires_at);
