-- name: CreateUser :one
INSERT INTO users (id, email, name, avatar_url, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: UserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: UserByID :one
SELECT * FROM users WHERE id = $1;

-- name: MarkEmailVerified :exec
UPDATE users SET email_verified_at = now(), updated_at = now() WHERE id = $1;

-- name: CreateSession :one
INSERT INTO sessions (id, user_id, token_hash, user_agent, ip, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, user_id, token_hash, user_agent, ip, created_at, expires_at, revoked_at, auth_level, active_organization_id;

-- name: SessionByTokenHash :one
SELECT id, user_id, token_hash, user_agent, ip, created_at, expires_at, revoked_at, auth_level, active_organization_id
FROM sessions WHERE token_hash = $1;

-- name: SessionByID :one
SELECT id, user_id, token_hash, user_agent, ip, created_at, expires_at, revoked_at, auth_level, active_organization_id
FROM sessions WHERE id = $1;

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = now() WHERE id = $1;

-- name: RevokeUserSessions :exec
UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: CreateMagicLink :exec
INSERT INTO magic_links (id, email, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: ConsumeMagicLink :one
UPDATE magic_links SET used_at = now()
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: SetUserPassword :exec
UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1;

-- name: UserByEmailWithPassword :one
SELECT id, email, email_verified_at, name, avatar_url, created_at, updated_at,
       COALESCE(password_hash, '') AS password_hash
FROM users WHERE email = $1;

-- name: CreatePasswordResetToken :exec
INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: ConsumePasswordResetToken :one
UPDATE password_reset_tokens SET used_at = now()
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: UpsertOAuthAccount :one
INSERT INTO oauth_accounts (
    id, user_id, provider, provider_user_id,
    access_token_enc, refresh_token_enc, expires_at, scope,
    created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (provider, provider_user_id) DO UPDATE SET
    user_id           = EXCLUDED.user_id,
    access_token_enc  = EXCLUDED.access_token_enc,
    refresh_token_enc = EXCLUDED.refresh_token_enc,
    expires_at        = EXCLUDED.expires_at,
    scope             = EXCLUDED.scope,
    updated_at        = now()
RETURNING *;

-- name: OAuthAccountByProviderUserID :one
SELECT * FROM oauth_accounts
WHERE provider = $1 AND provider_user_id = $2;

-- name: CreateSessionWithAuthLevel :one
INSERT INTO sessions (id, user_id, token_hash, user_agent, ip, created_at, expires_at, auth_level)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, user_id, token_hash, user_agent, ip, created_at, expires_at, revoked_at, auth_level, active_organization_id;

-- name: UpdateSessionAuthLevel :exec
UPDATE sessions SET auth_level = $2 WHERE id = $1;

-- name: InsertWebAuthnCredential :one
INSERT INTO webauthn_credentials (
    id, user_id, credential_id, public_key, sign_count,
    transports, aaguid, name, created_at, last_used_at,
    backup_eligible, backup_state
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: WebAuthnCredentialsByUserID :many
SELECT * FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at ASC;

-- name: WebAuthnCredentialByCredentialID :one
SELECT * FROM webauthn_credentials WHERE credential_id = $1;

-- name: UpdateWebAuthnSignCount :execrows
UPDATE webauthn_credentials
SET sign_count = $2, last_used_at = $3
WHERE credential_id = $1 AND sign_count < $2;

-- name: UpdateWebAuthnBackupFlags :execrows
UPDATE webauthn_credentials
SET backup_eligible = $2, backup_state = $3
WHERE credential_id = $1;

-- name: DeleteWebAuthnCredential :execrows
DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2;

-- name: UpsertPendingTOTPSecret :exec
INSERT INTO totp_secrets (user_id, secret_enc, confirmed_at, created_at, updated_at)
VALUES ($1, $2, NULL, $3, $3)
ON CONFLICT (user_id) DO UPDATE SET
    secret_enc = EXCLUDED.secret_enc,
    confirmed_at = NULL,
    updated_at = EXCLUDED.updated_at
WHERE totp_secrets.confirmed_at IS NULL;

-- name: ConfirmTOTPSecret :execrows
UPDATE totp_secrets SET confirmed_at = $2, updated_at = $2
WHERE user_id = $1 AND confirmed_at IS NULL;

-- name: TOTPSecretByUserID :one
SELECT * FROM totp_secrets WHERE user_id = $1;

-- name: DeleteTOTPSecret :exec
DELETE FROM totp_secrets WHERE user_id = $1;

-- name: DeleteRecoveryCodesByUserID :exec
DELETE FROM totp_recovery_codes WHERE user_id = $1;

-- name: InsertRecoveryCode :exec
INSERT INTO totp_recovery_codes (id, user_id, code_hash, created_at)
VALUES ($1, $2, $3, $4);

-- name: RecoveryCodesByUserID :many
SELECT * FROM totp_recovery_codes WHERE user_id = $1 AND used_at IS NULL;

-- name: ConsumeRecoveryCodeByID :execrows
UPDATE totp_recovery_codes SET used_at = $2
WHERE id = $1 AND used_at IS NULL;

-- ===== v0.7: organizations =====

-- name: InsertOrganization :one
INSERT INTO organizations (id, name, slug, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: OrganizationByID :one
SELECT * FROM organizations WHERE id = $1;

-- name: OrganizationBySlug :one
SELECT * FROM organizations WHERE slug = $1;

-- name: UpdateOrganization :execrows
UPDATE organizations SET name = $2, slug = $3, updated_at = now() WHERE id = $1;

-- name: DeleteOrganization :execrows
DELETE FROM organizations WHERE id = $1;

-- name: UpsertOrganizationMember :exec
INSERT INTO organization_members (organization_id, user_id, role, joined_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (organization_id, user_id) DO UPDATE SET role = EXCLUDED.role;

-- name: DeleteOrganizationMember :execrows
DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2;

-- name: OrganizationMembersByOrg :many
SELECT * FROM organization_members WHERE organization_id = $1 ORDER BY joined_at ASC;

-- name: OrganizationsByUser :many
SELECT o.* FROM organizations o
  JOIN organization_members m ON m.organization_id = o.id
 WHERE m.user_id = $1
 ORDER BY o.created_at ASC;

-- name: OrganizationMemberRole :one
SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2;

-- name: SetSessionActiveOrganization :execrows
UPDATE sessions SET active_organization_id = $2 WHERE id = $1;

-- ===== v0.7: saml =====

-- name: InsertSAMLConnection :one
INSERT INTO saml_connections (
    id, organization_id, idp_entity_id, idp_sso_url, idp_x509_cert,
    sp_entity_id, sp_acs_url, attribute_map, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: UpdateSAMLConnection :execrows
UPDATE saml_connections SET
    idp_entity_id = $2, idp_sso_url = $3, idp_x509_cert = $4,
    sp_entity_id = $5, sp_acs_url = $6, attribute_map = $7,
    updated_at = now()
WHERE id = $1;

-- name: DeleteSAMLConnection :execrows
DELETE FROM saml_connections WHERE id = $1;

-- name: SAMLConnectionByID :one
SELECT * FROM saml_connections WHERE id = $1;

-- name: SAMLConnectionsByOrg :many
SELECT * FROM saml_connections WHERE organization_id = $1 ORDER BY created_at ASC;

-- name: UpsertSAMLIdentity :one
INSERT INTO saml_identities (id, connection_id, user_id, name_id, name_id_format, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (connection_id, name_id) DO UPDATE SET
    user_id = EXCLUDED.user_id,
    name_id_format = EXCLUDED.name_id_format
RETURNING *;

-- name: SAMLIdentityByConnectionAndNameID :one
SELECT * FROM saml_identities WHERE connection_id = $1 AND name_id = $2;

-- name: TouchSAMLIdentityLastLogin :exec
UPDATE saml_identities SET last_login_at = $2 WHERE id = $1;

-- ===== v0.7: scim tokens =====

-- name: InsertSCIMToken :one
INSERT INTO scim_tokens (id, organization_id, token_hash, name, created_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: SCIMTokenByHash :one
SELECT * FROM scim_tokens WHERE token_hash = $1;

-- name: SCIMTokensByOrg :many
SELECT * FROM scim_tokens WHERE organization_id = $1 ORDER BY created_at ASC;

-- name: RevokeSCIMTokenByID :execrows
UPDATE scim_tokens SET revoked_at = $2 WHERE id = $1;

-- name: TouchSCIMTokenLastUsed :exec
UPDATE scim_tokens SET last_used_at = $2 WHERE id = $1;

-- ===== v0.7: users scoped queries =====

-- name: ListUsersByOrganization :many
SELECT u.* FROM users u
  JOIN organization_members m ON m.user_id = u.id
 WHERE m.organization_id = $1
   AND ($2::text = '' OR u.email = $2)
   AND ($3::text = '' OR u.external_id = $3)
   AND ($4::text = '' OR u.email = $4)
 ORDER BY u.created_at ASC
 OFFSET $5 LIMIT $6;

-- name: CountUsersByOrganization :one
SELECT count(*) FROM users u
  JOIN organization_members m ON m.user_id = u.id
 WHERE m.organization_id = $1
   AND ($2::text = '' OR u.email = $2)
   AND ($3::text = '' OR u.external_id = $3)
   AND ($4::text = '' OR u.email = $4);

-- name: UserByExternalIDInOrg :one
SELECT u.* FROM users u
  JOIN organization_members m ON m.user_id = u.id
 WHERE m.organization_id = $1 AND u.external_id = $2;

-- name: UpdateUserSCIM :execrows
UPDATE users SET
    email = $2, name = $3, avatar_url = $4,
    external_id = $5, given_name = $6, family_name = $7, display_name = $8,
    updated_at = now()
WHERE id = $1;

-- ===== v0.7: groups =====

-- name: InsertGroup :one
INSERT INTO groups (id, organization_id, display_name, external_id, created_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GroupByID :one
SELECT * FROM groups WHERE id = $1;

-- name: GroupByExternalIDInOrg :one
SELECT * FROM groups WHERE organization_id = $1 AND external_id = $2;

-- name: UpdateGroup :execrows
UPDATE groups SET display_name = $2, external_id = $3, updated_at = now() WHERE id = $1;

-- name: DeleteGroup :execrows
DELETE FROM groups WHERE id = $1;

-- name: ListGroupsByOrganization :many
SELECT * FROM groups
 WHERE organization_id = $1
   AND ($2::text = '' OR display_name = $2)
   AND ($3::text = '' OR external_id = $3)
 ORDER BY created_at ASC
 OFFSET $4 LIMIT $5;

-- name: CountGroupsByOrganization :one
SELECT count(*) FROM groups
 WHERE organization_id = $1
   AND ($2::text = '' OR display_name = $2)
   AND ($3::text = '' OR external_id = $3);

-- name: DeleteAllGroupMembers :exec
DELETE FROM group_members WHERE group_id = $1;

-- name: InsertGroupMember :exec
INSERT INTO group_members (group_id, user_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: DeleteGroupMember :exec
DELETE FROM group_members WHERE group_id = $1 AND user_id = $2;

-- name: GroupMembersByGroupID :many
SELECT user_id FROM group_members WHERE group_id = $1 ORDER BY user_id ASC;

-- ============================================================================
-- v1.0 RBAC
-- ============================================================================

-- name: InsertPermission :one
INSERT INTO permissions (id, name, description, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (name) DO UPDATE SET description = permissions.description
RETURNING id, name, description, created_at;

-- name: PermissionByName :one
SELECT id, name, description, created_at FROM permissions WHERE name = $1;

-- name: ListPermissions :many
SELECT id, name, description, created_at FROM permissions ORDER BY name ASC;

-- name: InsertRole :one
INSERT INTO roles (id, organization_id, name, description, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, organization_id, name, description, created_at, updated_at;

-- name: UpdateRoleRow :one
UPDATE roles SET name = $2, description = $3, updated_at = now() WHERE id = $1
RETURNING id, organization_id, name, description, created_at, updated_at;

-- name: DeleteRoleRow :execrows
DELETE FROM roles WHERE id = $1;

-- name: RoleByID :one
SELECT id, organization_id, name, description, created_at, updated_at FROM roles WHERE id = $1;

-- name: RoleByOrgAndName :one
SELECT id, organization_id, name, description, created_at, updated_at
  FROM roles
 WHERE name = $1
   AND ((organization_id IS NULL AND $2::uuid IS NULL) OR organization_id = $2::uuid);

-- name: RolesByOrganization :many
SELECT id, organization_id, name, description, created_at, updated_at
  FROM roles
 WHERE (organization_id IS NULL AND $1::uuid IS NULL) OR organization_id = $1::uuid
 ORDER BY name ASC;

-- name: DeleteRolePermissions :exec
DELETE FROM role_permissions WHERE role_id = $1;

-- name: InsertRolePermission :exec
INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: PermissionsByRoleID :many
SELECT p.name FROM permissions p
  JOIN role_permissions rp ON rp.permission_id = p.id
 WHERE rp.role_id = $1
 ORDER BY p.name ASC;

-- name: GrantUserRole :exec
INSERT INTO user_roles (user_id, role_id, granted_at, granted_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, role_id) DO NOTHING;

-- name: RevokeUserRole :execrows
DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2;

-- name: RolesForUser :many
SELECT r.id, r.organization_id, r.name, r.description, r.created_at, r.updated_at
  FROM roles r
  JOIN user_roles ur ON ur.role_id = r.id
 WHERE ur.user_id = $1
   AND ((r.organization_id IS NULL AND $2::uuid IS NULL) OR r.organization_id = $2::uuid)
 ORDER BY r.name ASC;

-- name: PermissionsForUserInOrg :many
SELECT DISTINCT p.name
  FROM permissions p
  JOIN role_permissions rp ON rp.permission_id = p.id
  JOIN user_roles ur ON ur.role_id = rp.role_id
  JOIN roles r ON r.id = rp.role_id
 WHERE ur.user_id = $1
   AND ((r.organization_id IS NULL AND $2::uuid IS NULL) OR r.organization_id = $2::uuid)
 ORDER BY p.name ASC;

-- name: CountUsersWithPermissionInOrg :one
SELECT count(DISTINCT ur.user_id) FROM user_roles ur
  JOIN role_permissions rp ON rp.role_id = ur.role_id
  JOIN permissions p ON p.id = rp.permission_id
  JOIN roles r ON r.id = ur.role_id
 WHERE p.name = $1 AND r.organization_id = $2;

-- ============================================================================
-- v1.0 Audit
-- ============================================================================

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (
    id, organization_id, actor_user_id, actor_session_id,
    action, target_type, target_id, metadata, ip, user_agent, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- The QueryAuditEvents read path is built dynamically in Go (filter combos vary
-- too much for a fixed sqlc query); the file storage/postgres/queries_v10.sql.go
-- emits the SQL directly via pgx with a where-builder.
