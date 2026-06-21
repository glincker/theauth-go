-- 0003: oauth accounts (v0.3)
--
-- Links a User to one or more remote OAuth provider identities. The
-- (provider, provider_user_id) pair is the natural key; running the OAuth
-- flow for the same provider account upserts this row rather than creating
-- a duplicate. Tokens are AES-GCM encrypted at the application layer; the
-- bytea columns include the 12-byte nonce prefix produced by crypto.Encrypt.

CREATE TABLE oauth_accounts (
    id                uuid PRIMARY KEY,
    user_id           uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider          text NOT NULL,
    provider_user_id  text NOT NULL,
    access_token_enc  bytea NOT NULL,
    refresh_token_enc bytea,
    expires_at        timestamptz,
    scope             text NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_user_id)
);

CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);
