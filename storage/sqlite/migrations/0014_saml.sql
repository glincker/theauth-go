-- 0014: SAML connections (one per organization and IdP) and the
-- (connection, NameID) to user identity map.
CREATE TABLE IF NOT EXISTS theauth_saml_connections (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES theauth_organizations (id) ON DELETE CASCADE,
    idp_entity_id   TEXT NOT NULL,
    idp_sso_url     TEXT NOT NULL,
    idp_x509_cert   TEXT NOT NULL,
    sp_entity_id    TEXT NOT NULL,
    sp_acs_url      TEXT NOT NULL,
    attribute_map   TEXT NOT NULL DEFAULT '{}',
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_saml_connections_org_idx ON theauth_saml_connections (organization_id);

CREATE TABLE IF NOT EXISTS theauth_saml_identities (
    id             TEXT PRIMARY KEY,
    connection_id  TEXT NOT NULL REFERENCES theauth_saml_connections (id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES theauth_users (id) ON DELETE CASCADE,
    name_id        TEXT NOT NULL,
    name_id_format TEXT NOT NULL DEFAULT '',
    last_login_at  INTEGER,
    created_at     INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_saml_identities_conn_name_uq ON theauth_saml_identities (connection_id, name_id);
CREATE INDEX IF NOT EXISTS theauth_saml_identities_user_idx ON theauth_saml_identities (user_id);
