-- 0034: two MySQL semantics fixes found by running the contract suite on a real server.
-- SAML NameIDs are case sensitive (SAML core 8.3), but the default collation folds case,
-- so NAME-1 matched name-1 and the (connection_id, name_id) unique key merged them.
ALTER TABLE saml_identities MODIFY name_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
-- System roles have a NULL organization_id, and a unique index treats NULLs as distinct, so
-- uq_roles_org_name never stopped duplicate system role names. A functional unique index
-- yields the name for system roles and NULL otherwise.
CREATE UNIQUE INDEX uq_roles_system_name ON roles ((CASE WHEN organization_id IS NULL THEN name END));
