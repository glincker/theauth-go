-- 0018: optional storage capabilities: session management and links, API
-- tokens (with agent columns), device codes, durable TOTP replay steps and
-- the shared login throttle table.

ALTER TABLE sessions
    ADD COLUMN last_seen_at    timestamptz,
    ADD COLUMN elevated_until  timestamptz,
    ADD COLUMN credential_id   text NOT NULL DEFAULT '';

CREATE INDEX idx_sessions_credential_id ON sessions (credential_id) WHERE credential_id <> '';

CREATE TABLE session_links (
    id            uuid PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    bytea NOT NULL,
    credential_id text NOT NULL DEFAULT '',
    session_ttl   bigint NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz
);

CREATE UNIQUE INDEX session_links_token_hash_uq ON session_links (token_hash);
CREATE INDEX idx_session_links_expires_at ON session_links (expires_at);

CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY,
    owner_id     uuid NOT NULL,
    owner_kind   text NOT NULL,
    name         text NOT NULL DEFAULT '',
    abilities    text NOT NULL DEFAULT '[]',
    token_hash   bytea NOT NULL,
    hint         text NOT NULL DEFAULT '',
    kind         text NOT NULL DEFAULT '',
    agent_name   text NOT NULL DEFAULT '',
    delegated_by uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz
);

CREATE UNIQUE INDEX api_tokens_hash_uq ON api_tokens (token_hash);
CREATE INDEX idx_api_tokens_owner ON api_tokens (owner_id);

CREATE TABLE device_codes (
    id                  uuid PRIMARY KEY,
    device_code_hash    bytea NOT NULL,
    user_code           text NOT NULL,
    status              text NOT NULL,
    client_name         text NOT NULL DEFAULT '',
    requested_abilities text NOT NULL DEFAULT '[]',
    approved_abilities  text NOT NULL DEFAULT '[]',
    approver_id         uuid,
    requester_ip        text NOT NULL DEFAULT '',
    requester_ua        text NOT NULL DEFAULT '',
    interval_seconds    integer NOT NULL DEFAULT 5,
    last_polled_at      timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL
);

CREATE UNIQUE INDEX device_codes_hash_uq ON device_codes (device_code_hash);
CREATE UNIQUE INDEX device_codes_user_code_uq ON device_codes (user_code);
CREATE INDEX idx_device_codes_expires_at ON device_codes (expires_at);

CREATE TABLE totp_last_steps (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    step    bigint NOT NULL
);

CREATE TABLE throttle_entries (
    key           text PRIMARY KEY,
    failures      integer NOT NULL,
    last_failure  bigint NOT NULL,
    blocked_until bigint NOT NULL,
    expires_at    bigint NOT NULL
);

CREATE INDEX idx_throttle_entries_expires_at ON throttle_entries (expires_at);
