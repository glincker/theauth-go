-- 0020: OAuth 2.1 authorization server clients (RFC 7591), including the
-- per-client access token policy (format, signing alg, RFC 9396 detail types)
-- and the OIDC client metadata document. List columns hold JSON arrays, times
-- are Unix microseconds, booleans are 0 or 1. owner_kind disambiguates the four
-- legal owners; exactly one owner id is set unless the client is anonymous.
-- Owner ids carry no foreign keys: the 0029 triggers remove a client when its
-- owning user or organization is deleted, and agents live in their own table.
CREATE TABLE IF NOT EXISTS theauth_oauth_clients (
    id                               TEXT PRIMARY KEY,
    client_id                        TEXT NOT NULL,
    client_secret_hash               BLOB,
    client_name                      TEXT NOT NULL DEFAULT '',
    redirect_uris                    TEXT NOT NULL DEFAULT '[]',
    grant_types                      TEXT NOT NULL DEFAULT '[]',
    response_types                   TEXT NOT NULL DEFAULT '[]',
    scope                            TEXT NOT NULL DEFAULT '',
    token_endpoint_auth_method       TEXT NOT NULL DEFAULT 'client_secret_basic',
    application_type                 TEXT NOT NULL DEFAULT 'web',
    contacts                         TEXT NOT NULL DEFAULT '[]',
    logo_uri                         TEXT NOT NULL DEFAULT '',
    policy_uri                       TEXT NOT NULL DEFAULT '',
    tos_uri                          TEXT NOT NULL DEFAULT '',
    jwks_uri                         TEXT NOT NULL DEFAULT '',
    jwks                             BLOB,
    software_id                      TEXT NOT NULL DEFAULT '',
    software_version                 TEXT NOT NULL DEFAULT '',
    owner_kind                       TEXT NOT NULL CHECK (owner_kind IN ('user', 'organization', 'agent', 'anonymous')),
    owner_user_id                    TEXT,
    owner_organization_id            TEXT,
    owner_agent_id                   TEXT,
    anonymous_registered             INTEGER NOT NULL DEFAULT 0,
    registration_access_hash         BLOB,
    created_at                       INTEGER NOT NULL,
    updated_at                       INTEGER NOT NULL,
    access_token_format              TEXT NOT NULL DEFAULT '',
    access_token_signed_response_alg TEXT NOT NULL DEFAULT '',
    authorization_details_types      TEXT NOT NULL DEFAULT '[]',
    oidc_metadata                    TEXT NOT NULL DEFAULT '{}',
    CHECK (
        (owner_kind = 'user'         AND owner_user_id         IS NOT NULL AND owner_organization_id IS NULL AND owner_agent_id IS NULL) OR
        (owner_kind = 'organization' AND owner_organization_id IS NOT NULL AND owner_user_id         IS NULL AND owner_agent_id IS NULL) OR
        (owner_kind = 'agent'        AND owner_agent_id        IS NOT NULL AND owner_user_id         IS NULL AND owner_organization_id IS NULL) OR
        (owner_kind = 'anonymous'    AND owner_user_id IS NULL AND owner_organization_id IS NULL AND owner_agent_id IS NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_oauth_clients_client_id_uq ON theauth_oauth_clients (client_id);
CREATE INDEX IF NOT EXISTS theauth_oauth_clients_owner_user_idx ON theauth_oauth_clients (owner_user_id);
CREATE INDEX IF NOT EXISTS theauth_oauth_clients_owner_org_idx ON theauth_oauth_clients (owner_organization_id);
CREATE INDEX IF NOT EXISTS theauth_oauth_clients_owner_agent_idx ON theauth_oauth_clients (owner_agent_id);
