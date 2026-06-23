-- 0001: core tables (users, sessions, magic_links).
-- MySQL 8.x dialect: BINARY(16) for UUIDs stored as ULID bytes,
-- DATETIME(6) for microsecond timestamps, VARCHAR for text fields.

CREATE TABLE IF NOT EXISTS users (
    id                 BINARY(16) PRIMARY KEY,
    email              VARCHAR(255) NOT NULL,
    email_verified_at  DATETIME(6),
    name               TEXT NOT NULL DEFAULT '',
    avatar_url         TEXT NOT NULL DEFAULT '',
    created_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_users_email (email)
);

CREATE TABLE IF NOT EXISTS sessions (
    id          BINARY(16) PRIMARY KEY,
    user_id     BINARY(16) NOT NULL,
    token_hash  VARBINARY(255) NOT NULL,
    user_agent  TEXT NOT NULL DEFAULT '',
    ip          VARCHAR(45),
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at  DATETIME(6) NOT NULL,
    revoked_at  DATETIME(6),
    auth_level  VARCHAR(32) NOT NULL DEFAULT 'full',
    active_organization_id BINARY(16),
    UNIQUE KEY uq_sessions_token_hash (token_hash),
    KEY idx_sessions_user_id (user_id),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS magic_links (
    id          BINARY(16) PRIMARY KEY,
    email       VARCHAR(255) NOT NULL,
    token_hash  VARBINARY(255) NOT NULL,
    expires_at  DATETIME(6) NOT NULL,
    used_at     DATETIME(6),
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_magic_links_token_hash (token_hash),
    KEY idx_magic_links_email (email)
);
