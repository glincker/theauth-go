-- 0008: scim tokens, groups, and external ids (v0.7)
--
-- scim_tokens.token_hash is sha256(token); the v0.7 spec documents the
-- rationale against argon2 (uniform 256-bit input; argon2 would only add
-- latency without measurably increasing security). last_used_at is bumped
-- on every successful auth so operators can rotate stale tokens.
--
-- groups are a SCIM-first concept; for v0.7 they are flat (no nesting),
-- scoped to one organization. group_members is a join table.
--
-- users gains external_id (nullable) plus the three SCIM-friendly name
-- columns (given_name, family_name, display_name). They are all optional;
-- non-SCIM signup paths leave them empty.

CREATE TABLE scim_tokens (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_hash      bytea NOT NULL UNIQUE,
    name            text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz,
    revoked_at      timestamptz
);

CREATE INDEX idx_scim_tokens_organization_id ON scim_tokens(organization_id);

CREATE TABLE groups (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    display_name    text NOT NULL,
    external_id     text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, display_name)
);

CREATE UNIQUE INDEX idx_groups_org_external_id
    ON groups(organization_id, external_id)
    WHERE external_id IS NOT NULL;

CREATE TABLE group_members (
    group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX idx_group_members_user_id ON group_members(user_id);

ALTER TABLE users ADD COLUMN external_id  text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN given_name   text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN family_name  text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN display_name text NOT NULL DEFAULT '';

-- Per-organization external_id uniqueness is enforced at the application
-- layer in the SCIM Users upsert path, because the scope (organization_id)
-- is not a column on users.
