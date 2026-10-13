-- 0024: constrained device identity. A device is registered by redeeming a
-- single-use join token and then authenticates with an RFC 7523 assertion
-- signed by its enrolled key. Join tokens are stored only as SHA-256 digests.
-- There are no foreign keys on organization_id or created_by (rows may outlive
-- the organization and the contract allows unknown ids).
CREATE TABLE IF NOT EXISTS iot_devices (
    id              uuid PRIMARY KEY,
    organization_id uuid,
    name            text NOT NULL DEFAULT '',
    spiffe_id       text,
    public_key_jwk  text NOT NULL,
    key_thumbprint  text NOT NULL,
    attestation     text NOT NULL DEFAULT 'join_token',
    scopes          text NOT NULL DEFAULT '[]',
    status          text NOT NULL DEFAULT 'active',
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz,
    revoked_at      timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS iot_devices_spiffe_uq ON iot_devices (spiffe_id);
CREATE INDEX IF NOT EXISTS idx_iot_devices_org ON iot_devices (organization_id, created_at DESC);

CREATE TABLE IF NOT EXISTS device_join_tokens (
    id              uuid PRIMARY KEY,
    token_hash      bytea NOT NULL,
    token_prefix    text NOT NULL DEFAULT '',
    organization_id uuid,
    name            text NOT NULL DEFAULT '',
    spiffe_id       text NOT NULL DEFAULT '',
    scopes          text NOT NULL DEFAULT '[]',
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    redeemed_at     timestamptz,
    device_id       uuid,
    revoked_at      timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS device_join_tokens_hash_uq ON device_join_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_device_join_tokens_org ON device_join_tokens (organization_id, created_at DESC);
