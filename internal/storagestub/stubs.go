// Package storagestub holds capability stubs that report ErrStorageMissingCapability.
package storagestub

import (
	"context"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

func missingCapability(name string) error {
	return fmt.Errorf("%w: %s", models.ErrStorageMissingCapability, name)
}

// OAuthAccount satisfies OAuthAccountStorage with methods that report ErrStorageMissingCapability.
type OAuthAccount struct{}

func (OAuthAccount) UpsertOAuthAccount(_ context.Context, _ models.OAuthAccount) (r0 models.OAuthAccount, err error) {
	err = missingCapability("OAuthAccountStorage")
	return
}

func (OAuthAccount) OAuthAccountByProviderUserID(_ context.Context, _ string, _ string) (r0 *models.OAuthAccount, err error) {
	err = missingCapability("OAuthAccountStorage")
	return
}

func (OAuthAccount) OAuthAccountsByUserID(_ context.Context, _ models.ULID) (r0 []models.OAuthAccount, err error) {
	err = missingCapability("OAuthAccountStorage")
	return
}

func (OAuthAccount) MoveOAuthAccount(_ context.Context, _ string, _ string, _ models.ULID) (err error) {
	err = missingCapability("OAuthAccountStorage")
	return
}

func (OAuthAccount) DeleteOAuthAccountByProvider(_ context.Context, _ models.ULID, _ string) (err error) {
	err = missingCapability("OAuthAccountStorage")
	return
}

// WebAuthn satisfies WebAuthnStorage with methods that report ErrStorageMissingCapability.
type WebAuthn struct{}

func (WebAuthn) MoveWebAuthnCredentials(_ context.Context, _ models.ULID, _ models.ULID) (err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

func (WebAuthn) InsertWebAuthnCredential(_ context.Context, _ models.WebAuthnCredential) (r0 models.WebAuthnCredential, err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

func (WebAuthn) WebAuthnCredentialsByUserID(_ context.Context, _ models.ULID) (r0 []models.WebAuthnCredential, err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

func (WebAuthn) WebAuthnCredentialByCredentialID(_ context.Context, _ []byte) (r0 *models.WebAuthnCredential, err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

func (WebAuthn) UpdateWebAuthnSignCount(_ context.Context, _ []byte, _ uint32, _ time.Time) (err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

func (WebAuthn) UpdateWebAuthnBackupFlags(_ context.Context, _ []byte, _ bool, _ bool) (err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

func (WebAuthn) DeleteWebAuthnCredential(_ context.Context, _ models.ULID, _ models.ULID) (err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

// TOTP satisfies TOTPStorage with methods that report ErrStorageMissingCapability.
type TOTP struct{}

func (TOTP) MoveTOTPSecret(_ context.Context, _ models.ULID, _ models.ULID) (err error) {
	err = missingCapability("TOTPStorage")
	return
}

func (TOTP) UpsertPendingTOTPSecret(_ context.Context, _ models.TOTPSecret) (err error) {
	err = missingCapability("TOTPStorage")
	return
}

func (TOTP) ConfirmTOTPSecret(_ context.Context, _ models.ULID, _ time.Time) (err error) {
	err = missingCapability("TOTPStorage")
	return
}

func (TOTP) TOTPSecretByUserID(_ context.Context, _ models.ULID) (r0 *models.TOTPSecret, err error) {
	err = missingCapability("TOTPStorage")
	return
}

func (TOTP) DeleteTOTPSecret(_ context.Context, _ models.ULID) (err error) {
	err = missingCapability("TOTPStorage")
	return
}

func (TOTP) InsertRecoveryCodes(_ context.Context, _ []models.RecoveryCode) (err error) {
	err = missingCapability("TOTPStorage")
	return
}

func (TOTP) ConsumeRecoveryCode(_ context.Context, _ models.ULID, _ string, _ time.Time) (err error) {
	err = missingCapability("TOTPStorage")
	return
}

// Organization satisfies OrganizationStorage with methods that report ErrStorageMissingCapability.
type Organization struct{}

func (Organization) InsertOrganization(_ context.Context, _ models.Organization) (r0 models.Organization, err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (Organization) OrganizationByID(_ context.Context, _ models.ULID) (r0 *models.Organization, err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (Organization) OrganizationBySlug(_ context.Context, _ string) (r0 *models.Organization, err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (Organization) UpdateOrganization(_ context.Context, _ models.Organization) (err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (Organization) DeleteOrganization(_ context.Context, _ models.ULID) (err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (Organization) UpsertOrganizationMember(_ context.Context, _ models.OrganizationMember) (err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (Organization) DeleteOrganizationMember(_ context.Context, _ models.ULID, _ models.ULID) (err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (Organization) OrganizationMembersByOrg(_ context.Context, _ models.ULID) (r0 []models.OrganizationMember, err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (Organization) OrganizationsByUser(_ context.Context, _ models.ULID) (r0 []models.Organization, err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (Organization) OrganizationMemberRole(_ context.Context, _ models.ULID, _ models.ULID) (r0 string, err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (Organization) SetSessionActiveOrganization(_ context.Context, _ models.ULID, _ *models.ULID) (err error) {
	err = missingCapability("OrganizationStorage")
	return
}

// SAML satisfies SAMLStorage with methods that report ErrStorageMissingCapability.
type SAML struct{}

func (SAML) InsertSAMLConnection(_ context.Context, _ models.SAMLConnection) (r0 models.SAMLConnection, err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (SAML) UpdateSAMLConnectionRow(_ context.Context, _ models.SAMLConnection) (err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (SAML) DeleteSAMLConnection(_ context.Context, _ models.ULID) (err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (SAML) SAMLConnectionByID(_ context.Context, _ models.ULID) (r0 *models.SAMLConnection, err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (SAML) SAMLConnectionsByOrg(_ context.Context, _ models.ULID) (r0 []models.SAMLConnection, err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (SAML) UpsertSAMLIdentity(_ context.Context, _ models.SAMLIdentity) (r0 models.SAMLIdentity, err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (SAML) SAMLIdentityByConnectionAndNameID(_ context.Context, _ models.ULID, _ string) (r0 *models.SAMLIdentity, err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (SAML) TouchSAMLIdentityLastLogin(_ context.Context, _ models.ULID, _ time.Time) (err error) {
	err = missingCapability("SAMLStorage")
	return
}

// SCIM satisfies SCIMStorage with methods that report ErrStorageMissingCapability.
type SCIM struct{}

func (SCIM) InsertSCIMToken(_ context.Context, _ models.SCIMToken) (r0 models.SCIMToken, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) SCIMTokenByHash(_ context.Context, _ []byte) (r0 *models.SCIMToken, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) SCIMTokensByOrg(_ context.Context, _ models.ULID) (r0 []models.SCIMToken, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) RevokeSCIMTokenByID(_ context.Context, _ models.ULID, _ time.Time) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) TouchSCIMTokenLastUsed(_ context.Context, _ models.ULID, _ time.Time) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) ListUsersByOrganization(_ context.Context, _ models.ULID, _ int, _ int, _ models.SCIMUserFilter) (r0 []models.User, r1 int, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) ListGroupsByOrganization(_ context.Context, _ models.ULID, _ int, _ int, _ models.SCIMGroupFilter) (r0 []models.Group, r1 int, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) UserByExternalIDInOrg(_ context.Context, _ models.ULID, _ string) (r0 *models.User, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) UpdateUserSCIM(_ context.Context, _ models.User) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) InsertGroup(_ context.Context, _ models.Group) (r0 models.Group, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) GroupByID(_ context.Context, _ models.ULID) (r0 *models.Group, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) GroupByExternalIDInOrg(_ context.Context, _ models.ULID, _ string) (r0 *models.Group, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) UpdateGroup(_ context.Context, _ models.Group) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) DeleteGroup(_ context.Context, _ models.ULID) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) SetGroupMembers(_ context.Context, _ models.ULID, _ []models.ULID) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) AddGroupMembers(_ context.Context, _ models.ULID, _ []models.ULID) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) RemoveGroupMembers(_ context.Context, _ models.ULID, _ []models.ULID) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (SCIM) GroupMembers(_ context.Context, _ models.ULID) (r0 []models.ULID, err error) {
	err = missingCapability("SCIMStorage")
	return
}

// RBAC satisfies RBACStorage with methods that report ErrStorageMissingCapability.
type RBAC struct{}

func (RBAC) InsertPermission(_ context.Context, _ models.Permission) (r0 models.Permission, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) PermissionByName(_ context.Context, _ string) (r0 *models.Permission, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) ListPermissions(_ context.Context) (r0 []models.Permission, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) InsertRole(_ context.Context, _ models.Role) (r0 models.Role, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) UpdateRoleRow(_ context.Context, _ models.Role) (r0 models.Role, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) DeleteRole(_ context.Context, _ models.ULID) (err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) RoleByID(_ context.Context, _ models.ULID) (r0 *models.Role, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) RoleByOrgAndName(_ context.Context, _ *models.ULID, _ string) (r0 *models.Role, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) RolesByOrganization(_ context.Context, _ *models.ULID) (r0 []models.Role, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) SetRolePermissions(_ context.Context, _ models.ULID, _ []models.ULID) (err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) PermissionsByRole(_ context.Context, _ models.ULID) (r0 []string, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) GrantUserRole(_ context.Context, _ models.UserRole) (err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) RevokeUserRole(_ context.Context, _ models.ULID, _ models.ULID) (err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) RolesForUser(_ context.Context, _ models.ULID, _ *models.ULID) (r0 []models.Role, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) PermissionsForUser(_ context.Context, _ models.ULID, _ *models.ULID) (r0 []string, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (RBAC) CountUsersWithPermissionInOrg(_ context.Context, _ models.ULID, _ string) (r0 int, err error) {
	err = missingCapability("RBACStorage")
	return
}

// Audit satisfies AuditStorage with methods that report ErrStorageMissingCapability.
type Audit struct{}

func (Audit) InsertAuditEvents(_ context.Context, _ []models.AuditEvent) (err error) {
	err = missingCapability("AuditStorage")
	return
}

func (Audit) QueryAuditEvents(_ context.Context, _ models.AuditQuery) (r0 []models.AuditEvent, r1 string, err error) {
	err = missingCapability("AuditStorage")
	return
}
