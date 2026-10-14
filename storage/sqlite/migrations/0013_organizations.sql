-- 0013: organizations, membership and the per-session active organization.
-- The active organization lives in its own table so the core sessions table
-- keeps its shape and hosts that never enable organizations are untouched.
CREATE TABLE IF NOT EXISTS theauth_organizations (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL COLLATE NOCASE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_organizations_slug_uq ON theauth_organizations (slug);

CREATE TABLE IF NOT EXISTS theauth_organization_members (
    organization_id TEXT NOT NULL REFERENCES theauth_organizations (id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES theauth_users (id) ON DELETE CASCADE,
    role            TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    joined_at       INTEGER NOT NULL,
    PRIMARY KEY (organization_id, user_id)
);

CREATE INDEX IF NOT EXISTS theauth_organization_members_user_idx ON theauth_organization_members (user_id);

CREATE TABLE IF NOT EXISTS theauth_session_organizations (
    session_id      TEXT PRIMARY KEY REFERENCES theauth_sessions (id) ON DELETE CASCADE,
    organization_id TEXT NOT NULL REFERENCES theauth_organizations (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS theauth_session_organizations_org_idx ON theauth_session_organizations (organization_id);
