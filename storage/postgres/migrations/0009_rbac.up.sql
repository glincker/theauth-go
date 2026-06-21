-- 0009: rbac (v1.0)
--
-- Permissions are global (no org scoping): a permission string means the same
-- thing in every org. Roles are org-scoped (organization_id NULL for system
-- roles like super_admin). Role names are unique per org; system roles share
-- the global namespace and use a partial unique index.

CREATE TABLE permissions (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE roles (
    id              uuid PRIMARY KEY,
    organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Per-org name uniqueness. NULL organization_id (system roles) cannot collide
-- with each other under the standard UNIQUE constraint because NULL is not
-- equal to NULL; we add a partial unique index to enforce uniqueness among
-- system roles separately.
CREATE UNIQUE INDEX uq_roles_org_name
    ON roles (organization_id, name)
    WHERE organization_id IS NOT NULL;
CREATE UNIQUE INDEX uq_roles_system_name
    ON roles (name)
    WHERE organization_id IS NULL;

CREATE TABLE role_permissions (
    role_id       uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at timestamptz NOT NULL DEFAULT now(),
    granted_by uuid REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
