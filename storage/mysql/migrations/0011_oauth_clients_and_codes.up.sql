-- 0011: OAuth 2.1 authorization server primitives.
-- text[] columns (redirect_uris, grant_types etc.) become JSON arrays.
-- BOOLEAN becomes TINYINT(1). RETURNING is not available; application layer
-- uses separate SELECT after INSERT where needed.

CREATE TABLE IF NOT EXISTS oauth_clients (
    id                          BINARY(16) PRIMARY KEY,
    client_id                   VARCHAR(255) NOT NULL,
    client_secret_hash          BLOB,
    client_name                 TEXT NOT NULL DEFAULT '',
    redirect_uris               JSON NOT NULL,
    grant_types                 JSON NOT NULL,
    response_types              JSON NOT NULL,
    scope                       TEXT NOT NULL DEFAULT '',
    token_endpoint_auth_method  VARCHAR(64) NOT NULL DEFAULT 'client_secret_basic',
    application_type            VARCHAR(32) NOT NULL DEFAULT 'web',
    contacts                    JSON NOT NULL,
    logo_uri                    TEXT NOT NULL DEFAULT '',
    policy_uri                  TEXT NOT NULL DEFAULT '',
    tos_uri                     TEXT NOT NULL DEFAULT '',
    jwks_uri                    TEXT NOT NULL DEFAULT '',
    jwks                        BLOB,
    software_id                 VARCHAR(255) NOT NULL DEFAULT '',
    software_version            VARCHAR(255) NOT NULL DEFAULT '',
    owner_kind                  VARCHAR(32) NOT NULL,
    owner_user_id               BINARY(16),
    owner_organization_id       BINARY(16),
    owner_agent_id              BINARY(16),
    anonymous_registered        TINYINT(1) NOT NULL DEFAULT 0,
    registration_access_hash    BLOB,
    created_at                  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at                  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_oauth_clients_client_id (client_id),
    KEY idx_oauth_clients_owner_user (owner_user_id),
    KEY idx_oauth_clients_owner_organization (owner_organization_id),
    KEY idx_oauth_clients_owner_agent (owner_agent_id),
    CONSTRAINT fk_oauth_clients_user FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_oauth_clients_org FOREIGN KEY (owner_organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    CONSTRAINT chk_oauth_clients_owner_kind CHECK (owner_kind IN ('user', 'organization', 'agent', 'anonymous'))
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code                  VARCHAR(255) PRIMARY KEY,
    client_id             VARCHAR(255) NOT NULL,
    user_id               BINARY(16) NOT NULL,
    organization_id       BINARY(16),
    redirect_uri          TEXT NOT NULL,
    scope                 JSON NOT NULL,
    resource              TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method VARCHAR(16) NOT NULL DEFAULT 'S256',
    nonce                 VARCHAR(255) NOT NULL DEFAULT '',
    expires_at            DATETIME(6) NOT NULL,
    created_at            DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_oauth_authorization_codes_expires (expires_at),
    CONSTRAINT fk_oauth_codes_client FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    CONSTRAINT fk_oauth_codes_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_oauth_codes_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id              BINARY(16) PRIMARY KEY,
    hash            VARBINARY(255) NOT NULL,
    family_id       BINARY(16) NOT NULL,
    client_id       VARCHAR(255) NOT NULL,
    user_id         BINARY(16),
    agent_id        BINARY(16),
    scope           JSON NOT NULL,
    resource        TEXT NOT NULL,
    parent_jti      VARCHAR(255) NOT NULL DEFAULT '',
    issued_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at      DATETIME(6) NOT NULL,
    revoked_at      DATETIME(6),
    revocation_note TEXT NOT NULL DEFAULT '',
    UNIQUE KEY uq_oauth_refresh_tokens_hash (hash),
    KEY idx_oauth_refresh_tokens_family (family_id),
    KEY idx_oauth_refresh_tokens_user (user_id),
    KEY idx_oauth_refresh_tokens_agent (agent_id),
    CONSTRAINT fk_oauth_refresh_tokens_client FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    CONSTRAINT fk_oauth_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
