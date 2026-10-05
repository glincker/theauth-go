-- 0018: optional storage capabilities: session management and links, API
-- tokens (with agent columns), device codes, durable TOTP replay steps and
-- the shared login throttle table.

ALTER TABLE sessions
    ADD COLUMN last_seen_at   DATETIME(6) NULL,
    ADD COLUMN elevated_until DATETIME(6) NULL,
    ADD COLUMN credential_id  VARCHAR(255) NOT NULL DEFAULT '',
    ADD KEY idx_sessions_credential_id (credential_id);

CREATE TABLE IF NOT EXISTS session_links (
    id            BINARY(16) PRIMARY KEY,
    user_id       BINARY(16) NOT NULL,
    token_hash    VARBINARY(255) NOT NULL,
    credential_id VARCHAR(255) NOT NULL DEFAULT '',
    session_ttl   BIGINT NOT NULL DEFAULT 0,
    created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at    DATETIME(6) NOT NULL,
    consumed_at   DATETIME(6) NULL,
    UNIQUE KEY uq_session_links_token_hash (token_hash),
    KEY idx_session_links_expires_at (expires_at),
    CONSTRAINT fk_session_links_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id           BINARY(16) PRIMARY KEY,
    owner_id     BINARY(16) NOT NULL,
    owner_kind   VARCHAR(32) NOT NULL,
    name         VARCHAR(255) NOT NULL DEFAULT '',
    abilities    TEXT NOT NULL,
    token_hash   VARBINARY(255) NOT NULL,
    hint         VARCHAR(255) NOT NULL DEFAULT '',
    kind         VARCHAR(32) NOT NULL DEFAULT '',
    agent_name   VARCHAR(255) NOT NULL DEFAULT '',
    delegated_by BINARY(16) NULL,
    created_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at   DATETIME(6) NULL,
    last_used_at DATETIME(6) NULL,
    revoked_at   DATETIME(6) NULL,
    UNIQUE KEY uq_api_tokens_hash (token_hash),
    KEY idx_api_tokens_owner (owner_id)
);

CREATE TABLE IF NOT EXISTS device_codes (
    id                  BINARY(16) PRIMARY KEY,
    device_code_hash    VARBINARY(255) NOT NULL,
    user_code           VARCHAR(64) NOT NULL,
    status              VARCHAR(16) NOT NULL,
    client_name         VARCHAR(255) NOT NULL DEFAULT '',
    requested_abilities TEXT NOT NULL,
    approved_abilities  TEXT NOT NULL,
    approver_id         BINARY(16) NULL,
    requester_ip        VARCHAR(255) NOT NULL DEFAULT '',
    requester_ua        TEXT NOT NULL,
    interval_seconds    INT NOT NULL DEFAULT 5,
    last_polled_at      DATETIME(6) NULL,
    created_at          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at          DATETIME(6) NOT NULL,
    UNIQUE KEY uq_device_codes_hash (device_code_hash),
    UNIQUE KEY uq_device_codes_user_code (user_code),
    KEY idx_device_codes_expires_at (expires_at)
);

CREATE TABLE IF NOT EXISTS totp_last_steps (
    user_id BINARY(16) PRIMARY KEY,
    step    BIGINT NOT NULL,
    CONSTRAINT fk_totp_last_steps_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS throttle_entries (
    entry_key     VARCHAR(255) PRIMARY KEY,
    failures      INT NOT NULL,
    last_failure  BIGINT NOT NULL,
    blocked_until BIGINT NOT NULL,
    expires_at    BIGINT NOT NULL,
    KEY idx_throttle_entries_expires_at (expires_at)
);
