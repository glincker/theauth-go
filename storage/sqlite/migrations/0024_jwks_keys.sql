-- 0024: JWKS signing keys for the authorization server. State machine:
-- next -> current -> previous -> retired. Private bytes are stored encrypted
-- by the caller. The partial unique index allows at most one current key per
-- algorithm, so a racing rotation cannot leave two current keys for one alg.
CREATE TABLE IF NOT EXISTS theauth_jwks_keys (
    kid         TEXT PRIMARY KEY,
    alg         TEXT NOT NULL,
    use_        TEXT NOT NULL DEFAULT 'sig',
    public_jwk  BLOB NOT NULL,
    private_enc BLOB NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('next', 'current', 'previous', 'retired')),
    created_at  INTEGER NOT NULL,
    promoted_at INTEGER,
    retired_at  INTEGER
);

CREATE INDEX IF NOT EXISTS theauth_jwks_keys_state_idx ON theauth_jwks_keys (state);
CREATE UNIQUE INDEX IF NOT EXISTS theauth_jwks_one_current_per_alg ON theauth_jwks_keys (alg) WHERE state = 'current';
