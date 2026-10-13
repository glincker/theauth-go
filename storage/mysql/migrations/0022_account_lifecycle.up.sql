-- 0022: account lifecycle flags (forced password change, disable) and
-- remember-this-device records.
CREATE TABLE IF NOT EXISTS account_states (
    user_id              BINARY(16) PRIMARY KEY,
    must_change_password TINYINT(1) NOT NULL DEFAULT 0,
    disabled_at          DATETIME(6) NULL,
    CONSTRAINT fk_account_states_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS trusted_devices (
    id           BINARY(16) PRIMARY KEY,
    user_id      BINARY(16) NOT NULL,
    token_hash   VARBINARY(255) NOT NULL,
    label        VARCHAR(255) NOT NULL DEFAULT '',
    user_agent   VARCHAR(512) NOT NULL DEFAULT '',
    ip           VARCHAR(64) NOT NULL DEFAULT '',
    created_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_used_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at   DATETIME(6) NOT NULL,
    revoked_at   DATETIME(6) NULL,
    UNIQUE KEY uq_trusted_devices_hash (token_hash),
    KEY idx_trusted_devices_user (user_id),
    CONSTRAINT fk_trusted_devices_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
