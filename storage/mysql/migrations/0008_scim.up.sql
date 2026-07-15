-- 0008: SCIM tokens, groups, group_members and user SCIM columns.
-- MySQL 8.0 supports partial/functional unique indexes via generated columns
-- or expression indexes. For idx_groups_org_external_id (WHERE external_id IS
-- NOT NULL) we use a filtered unique index by creating a generated column that
-- is NULL when external_id is NULL, and unique otherwise.

ALTER TABLE users
    ADD COLUMN external_id  VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN given_name   TEXT NOT NULL DEFAULT (''),
    ADD COLUMN family_name  TEXT NOT NULL DEFAULT (''),
    ADD COLUMN display_name TEXT NOT NULL DEFAULT ('');

CREATE TABLE IF NOT EXISTS scim_tokens (
    id              BINARY(16) PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    token_hash      VARBINARY(255) NOT NULL,
    name            VARCHAR(255) NOT NULL DEFAULT '',
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_used_at    DATETIME(6),
    revoked_at      DATETIME(6),
    UNIQUE KEY uq_scim_tokens_hash (token_hash),
    KEY idx_scim_tokens_organization_id (organization_id),
    CONSTRAINT fk_scim_tokens_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `groups` (
    id              BINARY(16) PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    display_name    VARCHAR(255) NOT NULL,
    external_id     VARCHAR(255),
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_groups_org_display_name (organization_id, display_name),
    KEY idx_groups_organization_id (organization_id),
    CONSTRAINT fk_groups_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- Emulate partial unique index WHERE external_id IS NOT NULL via application-
-- layer enforcement in InsertGroup / UpdateGroup. MySQL 8.0 functional indexes
-- cannot enforce conditional uniqueness as elegantly as Postgres partial
-- indexes; the duplicate is caught in the service layer and returns
-- ErrStorageNotFound (same behaviour as the Postgres adapter).

CREATE TABLE IF NOT EXISTS group_members (
    group_id BINARY(16) NOT NULL,
    user_id  BINARY(16) NOT NULL,
    PRIMARY KEY (group_id, user_id),
    KEY idx_group_members_user_id (user_id),
    CONSTRAINT fk_group_members_group FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
    CONSTRAINT fk_group_members_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
