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

-- name: CreateSessionWithAuthLevel :one
INSERT INTO sessions (id, user_id, token_hash, user_agent, ip, created_at, expires_at, auth_level)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: UpdateSessionAuthLevel :exec
UPDATE sessions SET auth_level = $2 WHERE id = $1;

-- name: InsertWebAuthnCredential :one
INSERT INTO webauthn_credentials (
    id, user_id, credential_id, public_key, sign_count,
    transports, aaguid, name, created_at, last_used_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: WebAuthnCredentialsByUserID :many
SELECT * FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at ASC;

-- name: WebAuthnCredentialByCredentialID :one
SELECT * FROM webauthn_credentials WHERE credential_id = $1;

-- name: UpdateWebAuthnSignCount :execrows
UPDATE webauthn_credentials
SET sign_count = $2, last_used_at = $3
WHERE credential_id = $1 AND sign_count < $2;

-- name: DeleteWebAuthnCredential :execrows
DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2;

-- name: UpsertPendingTOTPSecret :exec
INSERT INTO totp_secrets (user_id, secret_enc, confirmed_at, created_at, updated_at)
VALUES ($1, $2, NULL, $3, $3)
ON CONFLICT (user_id) DO UPDATE SET
    secret_enc = EXCLUDED.secret_enc,
    confirmed_at = NULL,
    updated_at = EXCLUDED.updated_at
WHERE totp_secrets.confirmed_at IS NULL;

-- name: ConfirmTOTPSecret :execrows
UPDATE totp_secrets SET confirmed_at = $2, updated_at = $2
WHERE user_id = $1 AND confirmed_at IS NULL;

-- name: TOTPSecretByUserID :one
SELECT * FROM totp_secrets WHERE user_id = $1;

-- name: DeleteTOTPSecret :exec
DELETE FROM totp_secrets WHERE user_id = $1;

-- name: DeleteRecoveryCodesByUserID :exec
DELETE FROM totp_recovery_codes WHERE user_id = $1;

-- name: InsertRecoveryCode :exec
INSERT INTO totp_recovery_codes (id, user_id, code_hash, created_at)
VALUES ($1, $2, $3, $4);

-- name: RecoveryCodesByUserID :many
SELECT * FROM totp_recovery_codes WHERE user_id = $1 AND used_at IS NULL;

-- name: ConsumeRecoveryCodeByID :execrows
UPDATE totp_recovery_codes SET used_at = $2
WHERE id = $1 AND used_at IS NULL;
