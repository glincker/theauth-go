-- 0022: account lifecycle flags (forced password change, disable) and
-- remember-this-device records.
CREATE TABLE IF NOT EXISTS account_states (
    user_id              uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    must_change_password boolean NOT NULL DEFAULT false,
    disabled_at          timestamptz
);

CREATE TABLE IF NOT EXISTS trusted_devices (
    id           uuid PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   bytea NOT NULL,
    label        text NOT NULL DEFAULT '',
    user_agent   text NOT NULL DEFAULT '',
    ip           text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS trusted_devices_hash_uq ON trusted_devices (token_hash);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices (user_id);
