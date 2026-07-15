-- 0009: RBAC (permissions, roles, role_permissions, user_roles).
-- Postgres uses partial unique indexes (WHERE organization_id IS NOT NULL /
-- IS NULL) to enforce per-org and system-role name uniqueness. MySQL 8.0
-- supports conditional unique indexes via generated columns. We use a simpler
-- approach: enforce the constraint in the application layer and rely on the
-- composite unique key below.

CREATE TABLE IF NOT EXISTS permissions (
    id          BINARY(16) PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT (''),
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_permissions_name (name)
);

CREATE TABLE IF NOT EXISTS roles (
    id              BINARY(16) PRIMARY KEY,
    organization_id BINARY(16),
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT (''),
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_roles_organization_id (organization_id),
    CONSTRAINT fk_roles_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- Per-org name uniqueness. Null org_id rows (system roles) tolerate
-- duplicates under a composite key because NULL != NULL in SQL.
-- Application layer enforces system-role name uniqueness.
CREATE UNIQUE INDEX uq_roles_org_name ON roles (organization_id, name);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       BINARY(16) NOT NULL,
    permission_id BINARY(16) NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permissions_perm FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id    BINARY(16) NOT NULL,
    role_id    BINARY(16) NOT NULL,
    granted_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    granted_by BINARY(16),
    PRIMARY KEY (user_id, role_id),
    KEY idx_user_roles_role_id (role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_granted_by FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL
);
