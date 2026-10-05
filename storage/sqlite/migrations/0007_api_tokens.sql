CREATE TABLE IF NOT EXISTS theauth_api_tokens (
    id           TEXT PRIMARY KEY,
    owner_id     TEXT NOT NULL,
    owner_kind   TEXT NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    abilities    TEXT NOT NULL DEFAULT '[]',
    token_hash   BLOB NOT NULL,
    hint         TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    last_used_at INTEGER,
    revoked_at   INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_api_tokens_hash_uq ON theauth_api_tokens (token_hash);
CREATE INDEX IF NOT EXISTS theauth_api_tokens_owner_idx ON theauth_api_tokens (owner_id);

CREATE TABLE IF NOT EXISTS theauth_device_codes (
    id                  TEXT PRIMARY KEY,
    device_code_hash    BLOB NOT NULL,
    user_code           TEXT NOT NULL,
    status              TEXT NOT NULL,
    client_name         TEXT NOT NULL DEFAULT '',
    requested_abilities TEXT NOT NULL DEFAULT '[]',
    approved_abilities  TEXT NOT NULL DEFAULT '[]',
    approver_id         TEXT,
    requester_ip        TEXT NOT NULL DEFAULT '',
    requester_ua        TEXT NOT NULL DEFAULT '',
    interval_seconds    INTEGER NOT NULL DEFAULT 5,
    last_polled_at      INTEGER,
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_device_codes_hash_uq ON theauth_device_codes (device_code_hash);
CREATE UNIQUE INDEX IF NOT EXISTS theauth_device_codes_user_code_uq ON theauth_device_codes (user_code);
CREATE INDEX IF NOT EXISTS theauth_device_codes_expires_idx ON theauth_device_codes (expires_at);
