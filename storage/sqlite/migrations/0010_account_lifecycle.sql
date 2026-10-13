-- 0010: account lifecycle flags (forced password change, disable) and
-- remember-this-device records.
CREATE TABLE IF NOT EXISTS theauth_account_states (
    user_id              TEXT PRIMARY KEY REFERENCES theauth_users (id) ON DELETE CASCADE,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    disabled_at          INTEGER
);

CREATE TABLE IF NOT EXISTS theauth_trusted_devices (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES theauth_users (id) ON DELETE CASCADE,
    token_hash   BLOB NOT NULL,
    label        TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT '',
    ip           TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_trusted_devices_hash_uq ON theauth_trusted_devices (token_hash);
CREATE INDEX IF NOT EXISTS theauth_trusted_devices_user_idx ON theauth_trusted_devices (user_id);
