-- 0028: initial access tokens for dynamic client registration. Only the token
-- hash is stored. Redemption is a conditional UPDATE bounded by max_uses.
-- No foreign keys: organization and creator ids are advisory.
CREATE TABLE IF NOT EXISTS theauth_registration_tokens (
    id              TEXT PRIMARY KEY,
    token_hash      BLOB NOT NULL,
    token_prefix    TEXT NOT NULL DEFAULT '',
    label           TEXT NOT NULL DEFAULT '',
    organization_id TEXT,
    scopes          TEXT NOT NULL DEFAULT '[]',
    grant_types     TEXT NOT NULL DEFAULT '[]',
    max_uses        INTEGER NOT NULL DEFAULT 1,
    uses            INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    last_used_at    INTEGER,
    revoked_at      INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_registration_tokens_hash_uq ON theauth_registration_tokens (token_hash);
CREATE INDEX IF NOT EXISTS theauth_registration_tokens_org_idx ON theauth_registration_tokens (organization_id, created_at DESC);
