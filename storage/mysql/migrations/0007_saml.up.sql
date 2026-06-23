-- 0007: SAML connections and identities.
-- attribute_map stores JSON (MySQL JSON type; equivalent to Postgres JSONB).
-- (connection_id, name_id) uniqueness enforced via composite unique index.

CREATE TABLE IF NOT EXISTS saml_connections (
    id              BINARY(16) PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    idp_entity_id   TEXT NOT NULL,
    idp_sso_url     TEXT NOT NULL,
    idp_x509_cert   TEXT NOT NULL,
    sp_entity_id    TEXT NOT NULL,
    sp_acs_url      TEXT NOT NULL,
    attribute_map   JSON NOT NULL,
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_saml_connections_organization_id (organization_id),
    CONSTRAINT fk_saml_connections_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS saml_identities (
    id              BINARY(16) PRIMARY KEY,
    connection_id   BINARY(16) NOT NULL,
    user_id         BINARY(16) NOT NULL,
    name_id         VARCHAR(255) NOT NULL,
    name_id_format  VARCHAR(255) NOT NULL DEFAULT '',
    last_login_at   DATETIME(6),
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_saml_identities_connection_name (connection_id, name_id),
    KEY idx_saml_identities_user_id (user_id),
    CONSTRAINT fk_saml_identities_connection FOREIGN KEY (connection_id) REFERENCES saml_connections(id) ON DELETE CASCADE,
    CONSTRAINT fk_saml_identities_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
