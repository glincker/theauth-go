CREATE TABLE IF NOT EXISTS theauth_totp_secrets (
    user_id      TEXT PRIMARY KEY REFERENCES theauth_users (id) ON DELETE CASCADE,
    secret_enc   BLOB NOT NULL,
    confirmed_at INTEGER,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_totp_recovery_codes (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES theauth_users (id) ON DELETE CASCADE,
    code_hash  BLOB NOT NULL,
    used_at    INTEGER,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_totp_recovery_codes_user_idx ON theauth_totp_recovery_codes (user_id);
