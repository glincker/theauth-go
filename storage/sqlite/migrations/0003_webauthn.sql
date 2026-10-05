CREATE TABLE IF NOT EXISTS theauth_webauthn_credentials (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES theauth_users (id) ON DELETE CASCADE,
    credential_id   BLOB NOT NULL,
    public_key      BLOB NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    transports      TEXT NOT NULL DEFAULT '[]',
    aaguid          BLOB NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL,
    last_used_at    INTEGER,
    backup_eligible INTEGER,
    backup_state    INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_webauthn_credential_id_uq ON theauth_webauthn_credentials (credential_id);
CREATE INDEX IF NOT EXISTS theauth_webauthn_user_idx ON theauth_webauthn_credentials (user_id);
