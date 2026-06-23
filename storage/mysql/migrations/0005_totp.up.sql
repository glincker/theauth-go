-- 0005: TOTP secrets and recovery codes.
-- secret_enc is AES-GCM encrypted. confirmed_at is NULL until enrollment is
-- confirmed. Recovery codes store salt(16)||sha256(salt||code)(32) as BLOB.

CREATE TABLE IF NOT EXISTS totp_secrets (
    user_id      BINARY(16) PRIMARY KEY,
    secret_enc   BLOB NOT NULL,
    confirmed_at DATETIME(6),
    created_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_totp_secrets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    id         BINARY(16) PRIMARY KEY,
    user_id    BINARY(16) NOT NULL,
    code_hash  BLOB NOT NULL,
    used_at    DATETIME(6),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_totp_recovery_codes_user_id (user_id),
    CONSTRAINT fk_totp_recovery_codes_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
