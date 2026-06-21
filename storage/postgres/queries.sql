-- name: CreateUser :one
INSERT INTO users (id, email, name, avatar_url, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: UserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: UserByID :one
SELECT * FROM users WHERE id = $1;

-- name: MarkEmailVerified :exec
UPDATE users SET email_verified_at = now(), updated_at = now() WHERE id = $1;

-- name: CreateSession :one
INSERT INTO sessions (id, user_id, token_hash, user_agent, ip, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: SessionByTokenHash :one
SELECT * FROM sessions WHERE token_hash = $1;

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = now() WHERE id = $1;

-- name: RevokeUserSessions :exec
UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: CreateMagicLink :exec
INSERT INTO magic_links (id, email, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: ConsumeMagicLink :one
UPDATE magic_links SET used_at = now()
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: SetUserPassword :exec
UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1;

-- name: UserByEmailWithPassword :one
SELECT id, email, email_verified_at, name, avatar_url, created_at, updated_at,
       COALESCE(password_hash, '') AS password_hash
FROM users WHERE email = $1;

-- name: CreatePasswordResetToken :exec
INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: ConsumePasswordResetToken :one
UPDATE password_reset_tokens SET used_at = now()
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: UpsertOAuthAccount :one
INSERT INTO oauth_accounts (
    id, user_id, provider, provider_user_id,
    access_token_enc, refresh_token_enc, expires_at, scope,
    created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (provider, provider_user_id) DO UPDATE SET
    user_id           = EXCLUDED.user_id,
    access_token_enc  = EXCLUDED.access_token_enc,
    refresh_token_enc = EXCLUDED.refresh_token_enc,
    expires_at        = EXCLUDED.expires_at,
    scope             = EXCLUDED.scope,
    updated_at        = now()
RETURNING *;

-- name: OAuthAccountByProviderUserID :one
SELECT * FROM oauth_accounts
WHERE provider = $1 AND provider_user_id = $2;
