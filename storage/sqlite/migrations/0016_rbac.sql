-- 0016: RBAC. Permissions are a global catalog; roles are organization
-- scoped, with a NULL organization meaning a system role. Requires 0013.
CREATE TABLE IF NOT EXISTS theauth_permissions (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_permissions_name_uq ON theauth_permissions (name);

CREATE TABLE IF NOT EXISTS theauth_roles (
    id              TEXT PRIMARY KEY,
    organization_id TEXT REFERENCES theauth_organizations (id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- NULL organizations never collide under a plain UNIQUE, so system roles get their own partial index.
CREATE UNIQUE INDEX IF NOT EXISTS theauth_roles_org_name_uq ON theauth_roles (organization_id, name)
    WHERE organization_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS theauth_roles_system_name_uq ON theauth_roles (name)
    WHERE organization_id IS NULL;

CREATE TABLE IF NOT EXISTS theauth_role_permissions (
    role_id       TEXT NOT NULL REFERENCES theauth_roles (id) ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES theauth_permissions (id) ON DELETE RESTRICT,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS theauth_user_roles (
    user_id    TEXT NOT NULL REFERENCES theauth_users (id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES theauth_roles (id) ON DELETE CASCADE,
    granted_at INTEGER NOT NULL,
    granted_by TEXT REFERENCES theauth_users (id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS theauth_user_roles_role_idx ON theauth_user_roles (role_id);
