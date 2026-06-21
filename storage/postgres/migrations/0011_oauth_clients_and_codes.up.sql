-- 0011: OAuth 2.1 authorization server primitives (v2.0 phase 1).
--
-- oauth_clients persists RFC 7591 dynamic registrations and operator-created
-- clients alike. owner_kind disambiguates the four legal owners; exactly one
-- of owner_user_id / owner_organization_id / owner_agent_id is non-null
-- (or all three are null when owner_kind = 'anonymous'). owner_agent_id is
-- nullable in this phase; the agents table itself ships in migration 0012
-- alongside phase 3's identity work.
--
-- oauth_authorization_codes are single-use, 60-second TTL by default. The
-- consume operation is atomic via DELETE ... RETURNING.
--
-- oauth_refresh_tokens are rotated on every use per RFC 9700 BCP section
-- 4.14. family_id links a chain of rotated tokens so a reuse detection can
-- revoke the whole family in one statement.

CREATE TABLE oauth_clients (
    id                          uuid PRIMARY KEY,
    client_id                   text NOT NULL UNIQUE,
    client_secret_hash          bytea,
    client_name                 text NOT NULL DEFAULT '',
    redirect_uris               text[] NOT NULL DEFAULT '{}',
    grant_types                 text[] NOT NULL DEFAULT '{}',
    response_types              text[] NOT NULL DEFAULT '{}',
    scope                       text NOT NULL DEFAULT '',
    token_endpoint_auth_method  text NOT NULL DEFAULT 'client_secret_basic',
    application_type            text NOT NULL DEFAULT 'web',
    contacts                    text[] NOT NULL DEFAULT '{}',
    logo_uri                    text NOT NULL DEFAULT '',
    policy_uri                  text NOT NULL DEFAULT '',
    tos_uri                     text NOT NULL DEFAULT '',
    jwks_uri                    text NOT NULL DEFAULT '',
    jwks                        bytea,
    software_id                 text NOT NULL DEFAULT '',
    software_version            text NOT NULL DEFAULT '',
    owner_kind                  text NOT NULL,
    owner_user_id               uuid REFERENCES users(id) ON DELETE CASCADE,
    owner_organization_id       uuid REFERENCES organizations(id) ON DELETE CASCADE,
    owner_agent_id              uuid,
    anonymous_registered        boolean NOT NULL DEFAULT false,
    registration_access_hash    bytea,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    CHECK (owner_kind IN ('user', 'organization', 'agent', 'anonymous')),
    CHECK (
        (owner_kind = 'user'         AND owner_user_id         IS NOT NULL AND owner_organization_id IS NULL AND owner_agent_id IS NULL) OR
        (owner_kind = 'organization' AND owner_organization_id IS NOT NULL AND owner_user_id         IS NULL AND owner_agent_id IS NULL) OR
        (owner_kind = 'agent'        AND owner_agent_id        IS NOT NULL AND owner_user_id         IS NULL AND owner_organization_id IS NULL) OR
        (owner_kind = 'anonymous'    AND owner_user_id IS NULL AND owner_organization_id IS NULL AND owner_agent_id IS NULL)
    )
);
CREATE INDEX idx_oauth_clients_owner_user         ON oauth_clients(owner_user_id);
CREATE INDEX idx_oauth_clients_owner_organization ON oauth_clients(owner_organization_id);
CREATE INDEX idx_oauth_clients_owner_agent        ON oauth_clients(owner_agent_id);

CREATE TABLE oauth_authorization_codes (
    code                  text PRIMARY KEY,
    client_id             text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id               uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id       uuid REFERENCES organizations(id) ON DELETE CASCADE,
    redirect_uri          text NOT NULL,
    scope                 text[] NOT NULL DEFAULT '{}',
    resource              text NOT NULL,
    code_challenge        text NOT NULL,
    code_challenge_method text NOT NULL DEFAULT 'S256',
    nonce                 text NOT NULL DEFAULT '',
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_oauth_authorization_codes_expires ON oauth_authorization_codes(expires_at);

CREATE TABLE oauth_refresh_tokens (
    id              uuid PRIMARY KEY,
    hash            bytea NOT NULL UNIQUE,
    family_id       uuid NOT NULL,
    client_id       text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id         uuid REFERENCES users(id) ON DELETE CASCADE,
    agent_id        uuid,
    scope           text[] NOT NULL DEFAULT '{}',
    resource        text NOT NULL,
    parent_jti      text NOT NULL DEFAULT '',
    issued_at       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    revocation_note text NOT NULL DEFAULT ''
);
CREATE INDEX idx_oauth_refresh_tokens_family ON oauth_refresh_tokens(family_id);
CREATE INDEX idx_oauth_refresh_tokens_user   ON oauth_refresh_tokens(user_id);
CREATE INDEX idx_oauth_refresh_tokens_agent  ON oauth_refresh_tokens(agent_id);
