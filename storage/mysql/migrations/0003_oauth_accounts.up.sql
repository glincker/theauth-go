-- 0003: OAuth provider accounts.
-- access_token_enc and refresh_token_enc are AES-GCM encrypted blobs.

CREATE TABLE IF NOT EXISTS oauth_accounts (
    id                BINARY(16) PRIMARY KEY,
    user_id           BINARY(16) NOT NULL,
    provider          VARCHAR(64) NOT NULL,
    provider_user_id  VARCHAR(255) NOT NULL,
    access_token_enc  BLOB NOT NULL,
    refresh_token_enc BLOB,
    expires_at        DATETIME(6),
    scope             TEXT NOT NULL DEFAULT (''),
    created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_oauth_accounts_provider (provider, provider_user_id),
    KEY idx_oauth_accounts_user_id (user_id),
    CONSTRAINT fk_oauth_accounts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
