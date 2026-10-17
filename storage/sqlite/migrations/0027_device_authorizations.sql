-- 0027: OAuth device authorization grant (RFC 8628). Codes are stored only as
-- keyed hashes. There are deliberately no foreign keys on client_id (CIMD
-- clients have no client row) or on user ids (rows are short lived and the
-- contract allows unknown ids). scope is a JSON array; times are Unix
-- microseconds.
CREATE TABLE IF NOT EXISTS theauth_device_authorizations (
    id               TEXT PRIMARY KEY,
    device_code_hash BLOB NOT NULL,
    user_code_hash   BLOB NOT NULL,
    client_id        TEXT NOT NULL,
    scope            TEXT NOT NULL DEFAULT '[]',
    resource         TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL,
    user_id          TEXT,
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_poll_at     INTEGER,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    decided_at       INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_device_authorizations_device_hash_uq ON theauth_device_authorizations (device_code_hash);
CREATE UNIQUE INDEX IF NOT EXISTS theauth_device_authorizations_user_hash_uq ON theauth_device_authorizations (user_code_hash);
CREATE INDEX IF NOT EXISTS theauth_device_authorizations_expires_idx ON theauth_device_authorizations (expires_at);
