-- 0019: OAuth device authorization grant (RFC 8628) and initial access tokens.
-- Codes are stored only as keyed hashes. No foreign keys on client_id (CIMD
-- clients have no oauth_clients row) or on user and organization ids.

CREATE TABLE IF NOT EXISTS device_authorizations (
    id               BINARY(16) PRIMARY KEY,
    device_code_hash VARBINARY(255) NOT NULL,
    user_code_hash   VARBINARY(255) NOT NULL,
    client_id        VARCHAR(512) NOT NULL,
    scope            TEXT NOT NULL,
    resource         VARCHAR(512) NOT NULL DEFAULT '',
    status           VARCHAR(16) NOT NULL,
    user_id          BINARY(16) NULL,
    interval_seconds INT NOT NULL DEFAULT 5,
    last_poll_at     DATETIME(6) NULL,
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at       DATETIME(6) NOT NULL,
    decided_at       DATETIME(6) NULL,
    UNIQUE KEY uq_device_authz_device_hash (device_code_hash),
    UNIQUE KEY uq_device_authz_user_hash (user_code_hash),
    KEY idx_device_authz_expires_at (expires_at)
);

CREATE TABLE IF NOT EXISTS registration_tokens (
    id              BINARY(16) PRIMARY KEY,
    token_hash      VARBINARY(255) NOT NULL,
    token_prefix    VARCHAR(32) NOT NULL DEFAULT '',
    label           VARCHAR(255) NOT NULL DEFAULT '',
    organization_id BINARY(16) NULL,
    scopes          TEXT NOT NULL,
    grant_types     TEXT NOT NULL,
    max_uses        INT NOT NULL DEFAULT 1,
    uses            INT NOT NULL DEFAULT 0,
    created_by      BINARY(16) NULL,
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at      DATETIME(6) NOT NULL,
    last_used_at    DATETIME(6) NULL,
    revoked_at      DATETIME(6) NULL,
    UNIQUE KEY uq_registration_tokens_hash (token_hash),
    KEY idx_registration_tokens_org (organization_id, created_at)
);
