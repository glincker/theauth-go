-- 0002: email + password auth (v0.2)
--
-- Adds optional password_hash to users (nullable so magic-link-only accounts
-- created under v0.1 still authenticate). Adds a separate password_reset_tokens
-- table so reset flows stay isolated from magic_links (different semantics:
-- reset tokens bind to an existing user_id, magic links bind to an email).

ALTER TABLE users ADD COLUMN password_hash text;

CREATE TABLE password_reset_tokens (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  bytea UNIQUE NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
