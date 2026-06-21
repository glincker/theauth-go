-- 0005: totp secrets, recovery codes, session auth_level (v0.5)
--
-- totp_secrets is keyed by user_id (one TOTP credential per user). secret_enc
-- is AES-GCM encrypted using Config.EncryptionKey (the same key OAuth tokens
-- ride on). confirmed_at is NULL until the user enters one valid code via
-- /auth/totp/enroll/finish; rows with confirmed_at IS NULL are ignored at
-- verify time and overwritten by a fresh /enroll/begin.
--
-- totp_recovery_codes holds 10 single-use codes per enrollment, each stored
-- as salt(16) || sha256(salt || code)(32). See crypto/recoverycode.go for
-- the rationale (40 bits of crypto/rand entropy makes Argon2id wasted
-- latency; per-code salt defeats rainbow tables).
--
-- sessions.auth_level gets a new column for the v0.5 state machine. Existing
-- rows default to "full" so the rollout is backward compatible.

CREATE TABLE totp_secrets (
    user_id      uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc   bytea NOT NULL,
    confirmed_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE totp_recovery_codes (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_totp_recovery_codes_user_id ON totp_recovery_codes(user_id);

ALTER TABLE sessions ADD COLUMN auth_level text NOT NULL DEFAULT 'full';
