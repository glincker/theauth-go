-- 0015: SCIM bearer tokens (sha256 hash only), groups and group membership.
-- Requires 0013. The SCIM user columns (external_id and the name parts)
-- already exist on theauth_users from 0001.
CREATE TABLE IF NOT EXISTS theauth_scim_tokens (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES theauth_organizations (id) ON DELETE CASCADE,
    token_hash      BLOB NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL,
    last_used_at    INTEGER,
    revoked_at      INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_scim_tokens_hash_uq ON theauth_scim_tokens (token_hash);
CREATE INDEX IF NOT EXISTS theauth_scim_tokens_org_idx ON theauth_scim_tokens (organization_id);

CREATE TABLE IF NOT EXISTS theauth_groups (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES theauth_organizations (id) ON DELETE CASCADE,
    display_name    TEXT NOT NULL,
    external_id     TEXT,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_groups_org_name_uq ON theauth_groups (organization_id, display_name);
CREATE UNIQUE INDEX IF NOT EXISTS theauth_groups_org_external_uq ON theauth_groups (organization_id, external_id)
    WHERE external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS theauth_group_members (
    group_id TEXT NOT NULL REFERENCES theauth_groups (id) ON DELETE CASCADE,
    user_id  TEXT NOT NULL REFERENCES theauth_users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS theauth_group_members_user_idx ON theauth_group_members (user_id);
