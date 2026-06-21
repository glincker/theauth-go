-- 0004: webauthn credentials (v0.5)
--
-- One row per registered authenticator. credential_id is the raw byte string
-- the authenticator returns at registration; we require uniqueness so a
-- stolen credential cannot be re-registered against a different user.
-- sign_count is monotonic per credential and rejected on equality (replay
-- detection). Authenticators that never implement sign counts always return
-- 0; the library carve-out is enforced at the service layer, not here.

CREATE TABLE webauthn_credentials (
    id            uuid PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    public_key    bytea NOT NULL,
    sign_count    bigint NOT NULL DEFAULT 0,
    transports    text[] NOT NULL DEFAULT '{}',
    aaguid        bytea NOT NULL,
    name          text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);

CREATE INDEX idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
