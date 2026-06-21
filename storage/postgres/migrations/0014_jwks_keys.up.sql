-- 0014: JWKS signing keys for the OAuth 2.1 authorization server (v2.0).
--
-- State machine: next -> current -> previous -> retired. The rotation
-- goroutine (jwks.go) drives the transitions every KeyRotationPeriod
-- (default 30 days). Private bytes arrive AES-GCM encrypted under
-- Config.EncryptionKey; the rotation never touches the disk-plaintext key.

CREATE TABLE jwks_keys (
    kid          text PRIMARY KEY,
    alg          text NOT NULL,
    use_         text NOT NULL DEFAULT 'sig',
    public_jwk   bytea NOT NULL,
    private_enc  bytea NOT NULL,
    state        text NOT NULL CHECK (state IN ('next','current','previous','retired')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    promoted_at  timestamptz,
    retired_at   timestamptz
);
CREATE INDEX idx_jwks_keys_state ON jwks_keys(state);
