-- 0006: organizations and membership.
-- MySQL enforces case-insensitive VARCHAR comparisons with utf8mb4_unicode_ci
-- collation (matching the citext behaviour in Postgres). The FK from sessions
-- uses ON DELETE SET NULL for active_organization_id.

CREATE TABLE IF NOT EXISTS organizations (
    id         BINARY(16) PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       VARCHAR(255) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_organizations_slug (slug)
);

CREATE TABLE IF NOT EXISTS organization_members (
    organization_id BINARY(16) NOT NULL,
    user_id         BINARY(16) NOT NULL,
    role            VARCHAR(16) NOT NULL,
    joined_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (organization_id, user_id),
    KEY idx_organization_members_user_id (user_id),
    CONSTRAINT fk_org_members_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    CONSTRAINT fk_org_members_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT chk_org_member_role CHECK (role IN ('owner', 'admin', 'member'))
);

ALTER TABLE sessions
    ADD CONSTRAINT fk_sessions_org
    FOREIGN KEY (active_organization_id) REFERENCES organizations(id) ON DELETE SET NULL;
