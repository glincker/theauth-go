-- 0002: email + password auth.
-- Passwords live in a separate table (not an ALTER on users) to keep the
-- identity table clean. password_hash stores the Argon2id PHC string.

CREATE TABLE IF NOT EXISTS user_passwords (
    user_id       BINARY(16) PRIMARY KEY,
    password_hash TEXT NOT NULL,
    CONSTRAINT fk_user_passwords_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          BINARY(16) PRIMARY KEY,
    user_id     BINARY(16) NOT NULL,
    token_hash  VARBINARY(255) NOT NULL,
    expires_at  DATETIME(6) NOT NULL,
    used_at     DATETIME(6),
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_password_reset_tokens_hash (token_hash),
    KEY idx_password_reset_tokens_user_id (user_id),
    CONSTRAINT fk_password_reset_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
