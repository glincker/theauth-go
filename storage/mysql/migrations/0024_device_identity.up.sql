-- 0024: constrained device identity. A device is registered by redeeming a
-- single-use join token and then authenticates with an RFC 7523 assertion
-- signed by its enrolled key. Join tokens are stored only as SHA-256 digests.
-- No foreign keys on organization_id or created_by. spiffe_id is NULL when
-- unset so the unique key only constrains assigned identities.
CREATE TABLE IF NOT EXISTS iot_devices (
    id              BINARY(16) PRIMARY KEY,
    organization_id BINARY(16) NULL,
    name            VARCHAR(255) NOT NULL DEFAULT '',
    spiffe_id       VARCHAR(512) NULL,
    public_key_jwk  TEXT NOT NULL,
    key_thumbprint  VARCHAR(128) NOT NULL,
    attestation     VARCHAR(64) NOT NULL DEFAULT 'join_token',
    scopes          TEXT NOT NULL,
    status          VARCHAR(16) NOT NULL DEFAULT 'active',
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen_at    DATETIME(6) NULL,
    revoked_at      DATETIME(6) NULL,
    UNIQUE KEY uq_iot_devices_spiffe (spiffe_id),
    KEY idx_iot_devices_org (organization_id, created_at)
);

CREATE TABLE IF NOT EXISTS device_join_tokens (
    id              BINARY(16) PRIMARY KEY,
    token_hash      VARBINARY(255) NOT NULL,
    token_prefix    VARCHAR(32) NOT NULL DEFAULT '',
    organization_id BINARY(16) NULL,
    name            VARCHAR(255) NOT NULL DEFAULT '',
    spiffe_id       VARCHAR(512) NOT NULL DEFAULT '',
    scopes          TEXT NOT NULL,
    created_by      BINARY(16) NULL,
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at      DATETIME(6) NOT NULL,
    redeemed_at     DATETIME(6) NULL,
    device_id       BINARY(16) NULL,
    revoked_at      DATETIME(6) NULL,
    UNIQUE KEY uq_device_join_tokens_hash (token_hash),
    KEY idx_device_join_tokens_org (organization_id, created_at)
);
