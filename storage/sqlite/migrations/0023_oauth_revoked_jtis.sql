-- 0023: access token denylist backing opt-in access token revocation. An entry
-- is keyed by the token jti and lapses at the token's own expiry, so the table
-- only ever holds live revocations; writers prune lapsed rows opportunistically.
CREATE TABLE IF NOT EXISTS theauth_oauth_revoked_jtis (
    jti        TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_oauth_revoked_jtis_expires_idx ON theauth_oauth_revoked_jtis (expires_at);
