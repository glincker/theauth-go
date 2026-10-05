CREATE TABLE IF NOT EXISTS theauth_totp_last_steps (
    user_id TEXT PRIMARY KEY REFERENCES theauth_users (id) ON DELETE CASCADE,
    step    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_throttle_entries (
    key           TEXT PRIMARY KEY,
    failures      INTEGER NOT NULL,
    last_failure  INTEGER NOT NULL,
    blocked_until INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_throttle_entries_expires_idx ON theauth_throttle_entries (expires_at);
