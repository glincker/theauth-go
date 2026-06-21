-- 0006: organizations (v0.7)
--
-- Multi-tenancy foundation. Single-tenant deployments that never insert a
-- row here continue to work unchanged: sessions.active_organization_id stays
-- NULL, the SAML and SCIM endpoints are not mounted by Mount() unless
-- Config.Organizations is non-nil, and every existing query that selects
-- from users / sessions / oauth_accounts / etc. is untouched.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE organizations (
    id         uuid PRIMARY KEY,
    name       text NOT NULL,
    slug       citext NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organization_members (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    joined_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);

CREATE INDEX idx_organization_members_user_id ON organization_members(user_id);

-- sessions gains a nullable active organization. Nullable + ON DELETE SET
-- NULL means deleting an organization revokes the active-org context on
-- each session without revoking the session itself.
ALTER TABLE sessions
    ADD COLUMN active_organization_id uuid REFERENCES organizations(id) ON DELETE SET NULL;
