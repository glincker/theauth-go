-- 0034: two MySQL semantics fixes found by running the contract suite on a real server.
-- SAML NameIDs are case sensitive (SAML core 8.3), but the default collation folds case,
-- so NAME-1 matched name-1 and the (connection_id, name_id) unique key merged them.
ALTER TABLE saml_identities MODIFY name_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
-- System roles have a NULL organization_id, and a unique index treats NULLs as distinct, so
-- uq_roles_org_name never stopped duplicate system role names. Databases written by an older
-- release can therefore hold duplicates (a check then insert race, or names that differ only by
-- case under the default collation), and creating the unique index over them fails with error
-- 1062. Merge each group into its lowest id first: members and permissions move to the survivor
-- (INSERT IGNORE skips pairs it already has), then the extra rows are deleted, which cascades.
INSERT IGNORE INTO user_roles (user_id, role_id, granted_at, granted_by)
SELECT ur.user_id, k.keep_id, ur.granted_at, ur.granted_by
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id AND r.organization_id IS NULL
JOIN (SELECT name, MIN(id) AS keep_id FROM roles WHERE organization_id IS NULL GROUP BY name) k ON k.name = r.name
WHERE r.id <> k.keep_id;
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT k.keep_id, rp.permission_id
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.organization_id IS NULL
JOIN (SELECT name, MIN(id) AS keep_id FROM roles WHERE organization_id IS NULL GROUP BY name) k ON k.name = r.name
WHERE r.id <> k.keep_id;
DELETE r FROM roles r
JOIN (SELECT name, MIN(id) AS keep_id FROM roles WHERE organization_id IS NULL GROUP BY name) k ON k.name = r.name
WHERE r.organization_id IS NULL AND r.id <> k.keep_id;
-- A functional unique index yields the name for system roles and NULL otherwise.
CREATE UNIQUE INDEX uq_roles_system_name ON roles ((CASE WHEN organization_id IS NULL THEN name END));
