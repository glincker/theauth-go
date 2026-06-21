-- 0007: saml connections and identities (v0.7)
--
-- One row per (organization, IdP) binding. idp_x509_cert is PEM text; we
-- store the full cert (not just a fingerprint) so the crewjam/saml
-- ServiceProvider can be rebuilt from a single row.
--
-- saml_identities is the find-or-create key: (connection_id, name_id) ->
-- user_id. name_id is whatever the IdP put in Subject.NameID.Value; for
-- common formats this is opaque and stable across sessions.

CREATE TABLE saml_connections (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    idp_entity_id   text NOT NULL,
    idp_sso_url     text NOT NULL,
    idp_x509_cert   text NOT NULL,
    sp_entity_id    text NOT NULL,
    sp_acs_url      text NOT NULL,
    attribute_map   jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_saml_connections_organization_id ON saml_connections(organization_id);

CREATE TABLE saml_identities (
    id              uuid PRIMARY KEY,
    connection_id   uuid NOT NULL REFERENCES saml_connections(id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_id         text NOT NULL,
    name_id_format  text NOT NULL DEFAULT '',
    last_login_at   timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (connection_id, name_id)
);

CREATE INDEX idx_saml_identities_user_id ON saml_identities(user_id);
