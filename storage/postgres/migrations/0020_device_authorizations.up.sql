-- 0019: OAuth device authorization grant (RFC 8628) and initial access tokens.
-- Codes are stored only as keyed hashes. There are deliberately no foreign keys
-- on client_id (CIMD clients have no oauth_clients row) or on user and
-- organization ids (rows are short lived and the contract allows unknown ids).

CREATE TABLE device_authorizations (
    id               uuid PRIMARY KEY,
    device_code_hash bytea NOT NULL,
    user_code_hash   bytea NOT NULL,
    client_id        text NOT NULL,
    scope            text NOT NULL DEFAULT '[]',
    resource         text NOT NULL DEFAULT '',
    status           text NOT NULL,
    user_id          uuid,
    interval_seconds integer NOT NULL DEFAULT 5,
    last_poll_at     timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    decided_at       timestamptz
);

CREATE UNIQUE INDEX device_authorizations_device_hash_uq ON device_authorizations (device_code_hash);
CREATE UNIQUE INDEX device_authorizations_user_hash_uq ON device_authorizations (user_code_hash);
CREATE INDEX idx_device_authorizations_expires_at ON device_authorizations (expires_at);

CREATE TABLE registration_tokens (
    id              uuid PRIMARY KEY,
    token_hash      bytea NOT NULL,
    token_prefix    text NOT NULL DEFAULT '',
    label           text NOT NULL DEFAULT '',
    organization_id uuid,
    scopes          text NOT NULL DEFAULT '[]',
    grant_types     text NOT NULL DEFAULT '[]',
    max_uses        integer NOT NULL DEFAULT 1,
    uses            integer NOT NULL DEFAULT 0,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    last_used_at    timestamptz,
    revoked_at      timestamptz
);

CREATE UNIQUE INDEX registration_tokens_hash_uq ON registration_tokens (token_hash);
CREATE INDEX idx_registration_tokens_org ON registration_tokens (organization_id, created_at DESC);
