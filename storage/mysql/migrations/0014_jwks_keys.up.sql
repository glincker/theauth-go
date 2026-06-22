-- 0014: JWKS signing keys.
-- State machine: next -> current -> previous -> retired.
-- MySQL does not support partial unique indexes (WHERE state='current') the
-- same way Postgres does. Uniqueness of a single 'current' key is enforced at
-- the application layer in UpdateJWKSKeyState via an advisory lock / SELECT
-- FOR UPDATE pattern within the Migrate transaction. This matches the
-- Postgres adapter's AtomicRotateJWKS semantics.

CREATE TABLE IF NOT EXISTS jwks_keys (
    kid          VARCHAR(255) PRIMARY KEY,
    alg          VARCHAR(32) NOT NULL,
    use_         VARCHAR(8) NOT NULL DEFAULT 'sig',
    public_jwk   BLOB NOT NULL,
    private_enc  BLOB NOT NULL,
    state        VARCHAR(16) NOT NULL,
    created_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    promoted_at  DATETIME(6),
    retired_at   DATETIME(6),
    KEY idx_jwks_keys_state (state),
    CONSTRAINT chk_jwks_keys_state CHECK (state IN ('next', 'current', 'previous', 'retired'))
);
