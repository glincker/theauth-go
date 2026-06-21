ALTER TABLE sessions DROP COLUMN IF EXISTS active_organization_id;
DROP TABLE IF EXISTS organization_members;
DROP TABLE IF EXISTS organizations;
-- citext extension is not dropped; other schemas may depend on it.
