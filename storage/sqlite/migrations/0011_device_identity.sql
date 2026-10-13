-- 0011: constrained device identity. A device is registered by redeeming a
-- single-use join token and then authenticates with an RFC 7523 assertion
-- signed by its enrolled key. Join tokens are stored only as SHA-256 digests.
-- No foreign keys on organization_id or created_by: rows may outlive them.
CREATE TABLE IF NOT EXISTS theauth_iot_devices (
    id              TEXT PRIMARY KEY,
    organization_id TEXT,
    name            TEXT NOT NULL DEFAULT '',
    spiffe_id       TEXT,
    public_key_jwk  TEXT NOT NULL,
    key_thumbprint  TEXT NOT NULL,
    attestation     TEXT NOT NULL DEFAULT 'join_token',
    scopes          TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER,
    revoked_at      INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_iot_devices_spiffe_uq ON theauth_iot_devices (spiffe_id);
CREATE INDEX IF NOT EXISTS theauth_iot_devices_org_idx ON theauth_iot_devices (organization_id, created_at DESC);

CREATE TABLE IF NOT EXISTS theauth_device_join_tokens (
    id              TEXT PRIMARY KEY,
    token_hash      BLOB NOT NULL,
    token_prefix    TEXT NOT NULL DEFAULT '',
    organization_id TEXT,
    name            TEXT NOT NULL DEFAULT '',
    spiffe_id       TEXT NOT NULL DEFAULT '',
    scopes          TEXT NOT NULL DEFAULT '[]',
    created_by      TEXT,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    redeemed_at     INTEGER,
    device_id       TEXT,
    revoked_at      INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_device_join_tokens_hash_uq ON theauth_device_join_tokens (token_hash);
CREATE INDEX IF NOT EXISTS theauth_device_join_tokens_org_idx ON theauth_device_join_tokens (organization_id, created_at DESC);
