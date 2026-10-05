package theauth

import (
	"context"
	"time"
)

// unsupportedOAuthAccountStorage satisfies OAuthAccountStorage with methods that report ErrStorageMissingCapability.
type unsupportedOAuthAccountStorage struct{}

func (unsupportedOAuthAccountStorage) UpsertOAuthAccount(_ context.Context, _ OAuthAccount) (r0 OAuthAccount, err error) {
	err = missingCapability("OAuthAccountStorage")
	return
}

func (unsupportedOAuthAccountStorage) OAuthAccountByProviderUserID(_ context.Context, _ string, _ string) (r0 *OAuthAccount, err error) {
	err = missingCapability("OAuthAccountStorage")
	return
}

func (unsupportedOAuthAccountStorage) OAuthAccountsByUserID(_ context.Context, _ ULID) (r0 []OAuthAccount, err error) {
	err = missingCapability("OAuthAccountStorage")
	return
}

func (unsupportedOAuthAccountStorage) MoveOAuthAccount(_ context.Context, _ string, _ string, _ ULID) (err error) {
	err = missingCapability("OAuthAccountStorage")
	return
}

func (unsupportedOAuthAccountStorage) DeleteOAuthAccountByProvider(_ context.Context, _ ULID, _ string) (err error) {
	err = missingCapability("OAuthAccountStorage")
	return
}

// unsupportedWebAuthnStorage satisfies WebAuthnStorage with methods that report ErrStorageMissingCapability.
type unsupportedWebAuthnStorage struct{}

func (unsupportedWebAuthnStorage) MoveWebAuthnCredentials(_ context.Context, _ ULID, _ ULID) (err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

func (unsupportedWebAuthnStorage) InsertWebAuthnCredential(_ context.Context, _ WebAuthnCredential) (r0 WebAuthnCredential, err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

func (unsupportedWebAuthnStorage) WebAuthnCredentialsByUserID(_ context.Context, _ ULID) (r0 []WebAuthnCredential, err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

func (unsupportedWebAuthnStorage) WebAuthnCredentialByCredentialID(_ context.Context, _ []byte) (r0 *WebAuthnCredential, err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

func (unsupportedWebAuthnStorage) UpdateWebAuthnSignCount(_ context.Context, _ []byte, _ uint32, _ time.Time) (err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

func (unsupportedWebAuthnStorage) UpdateWebAuthnBackupFlags(_ context.Context, _ []byte, _ bool, _ bool) (err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

func (unsupportedWebAuthnStorage) DeleteWebAuthnCredential(_ context.Context, _ ULID, _ ULID) (err error) {
	err = missingCapability("WebAuthnStorage")
	return
}

// unsupportedTOTPStorage satisfies TOTPStorage with methods that report ErrStorageMissingCapability.
type unsupportedTOTPStorage struct{}

func (unsupportedTOTPStorage) MoveTOTPSecret(_ context.Context, _ ULID, _ ULID) (err error) {
	err = missingCapability("TOTPStorage")
	return
}

func (unsupportedTOTPStorage) UpsertPendingTOTPSecret(_ context.Context, _ TOTPSecret) (err error) {
	err = missingCapability("TOTPStorage")
	return
}

func (unsupportedTOTPStorage) ConfirmTOTPSecret(_ context.Context, _ ULID, _ time.Time) (err error) {
	err = missingCapability("TOTPStorage")
	return
}

func (unsupportedTOTPStorage) TOTPSecretByUserID(_ context.Context, _ ULID) (r0 *TOTPSecret, err error) {
	err = missingCapability("TOTPStorage")
	return
}

func (unsupportedTOTPStorage) DeleteTOTPSecret(_ context.Context, _ ULID) (err error) {
	err = missingCapability("TOTPStorage")
	return
}

func (unsupportedTOTPStorage) InsertRecoveryCodes(_ context.Context, _ []RecoveryCode) (err error) {
	err = missingCapability("TOTPStorage")
	return
}

func (unsupportedTOTPStorage) ConsumeRecoveryCode(_ context.Context, _ ULID, _ string, _ time.Time) (err error) {
	err = missingCapability("TOTPStorage")
	return
}

// unsupportedOrganizationStorage satisfies OrganizationStorage with methods that report ErrStorageMissingCapability.
type unsupportedOrganizationStorage struct{}

func (unsupportedOrganizationStorage) InsertOrganization(_ context.Context, _ Organization) (r0 Organization, err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (unsupportedOrganizationStorage) OrganizationByID(_ context.Context, _ ULID) (r0 *Organization, err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (unsupportedOrganizationStorage) OrganizationBySlug(_ context.Context, _ string) (r0 *Organization, err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (unsupportedOrganizationStorage) UpdateOrganization(_ context.Context, _ Organization) (err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (unsupportedOrganizationStorage) DeleteOrganization(_ context.Context, _ ULID) (err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (unsupportedOrganizationStorage) UpsertOrganizationMember(_ context.Context, _ OrganizationMember) (err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (unsupportedOrganizationStorage) DeleteOrganizationMember(_ context.Context, _ ULID, _ ULID) (err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (unsupportedOrganizationStorage) OrganizationMembersByOrg(_ context.Context, _ ULID) (r0 []OrganizationMember, err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (unsupportedOrganizationStorage) OrganizationsByUser(_ context.Context, _ ULID) (r0 []Organization, err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (unsupportedOrganizationStorage) OrganizationMemberRole(_ context.Context, _ ULID, _ ULID) (r0 string, err error) {
	err = missingCapability("OrganizationStorage")
	return
}

func (unsupportedOrganizationStorage) SetSessionActiveOrganization(_ context.Context, _ ULID, _ *ULID) (err error) {
	err = missingCapability("OrganizationStorage")
	return
}

// unsupportedSAMLStorage satisfies SAMLStorage with methods that report ErrStorageMissingCapability.
type unsupportedSAMLStorage struct{}

func (unsupportedSAMLStorage) InsertSAMLConnection(_ context.Context, _ SAMLConnection) (r0 SAMLConnection, err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (unsupportedSAMLStorage) UpdateSAMLConnectionRow(_ context.Context, _ SAMLConnection) (err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (unsupportedSAMLStorage) DeleteSAMLConnection(_ context.Context, _ ULID) (err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (unsupportedSAMLStorage) SAMLConnectionByID(_ context.Context, _ ULID) (r0 *SAMLConnection, err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (unsupportedSAMLStorage) SAMLConnectionsByOrg(_ context.Context, _ ULID) (r0 []SAMLConnection, err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (unsupportedSAMLStorage) UpsertSAMLIdentity(_ context.Context, _ SAMLIdentity) (r0 SAMLIdentity, err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (unsupportedSAMLStorage) SAMLIdentityByConnectionAndNameID(_ context.Context, _ ULID, _ string) (r0 *SAMLIdentity, err error) {
	err = missingCapability("SAMLStorage")
	return
}

func (unsupportedSAMLStorage) TouchSAMLIdentityLastLogin(_ context.Context, _ ULID, _ time.Time) (err error) {
	err = missingCapability("SAMLStorage")
	return
}

// unsupportedSCIMStorage satisfies SCIMStorage with methods that report ErrStorageMissingCapability.
type unsupportedSCIMStorage struct{}

func (unsupportedSCIMStorage) InsertSCIMToken(_ context.Context, _ SCIMToken) (r0 SCIMToken, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) SCIMTokenByHash(_ context.Context, _ []byte) (r0 *SCIMToken, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) SCIMTokensByOrg(_ context.Context, _ ULID) (r0 []SCIMToken, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) RevokeSCIMTokenByID(_ context.Context, _ ULID, _ time.Time) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) TouchSCIMTokenLastUsed(_ context.Context, _ ULID, _ time.Time) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) ListUsersByOrganization(_ context.Context, _ ULID, _ int, _ int, _ SCIMUserFilter) (r0 []User, r1 int, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) ListGroupsByOrganization(_ context.Context, _ ULID, _ int, _ int, _ SCIMGroupFilter) (r0 []Group, r1 int, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) UserByExternalIDInOrg(_ context.Context, _ ULID, _ string) (r0 *User, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) UpdateUserSCIM(_ context.Context, _ User) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) InsertGroup(_ context.Context, _ Group) (r0 Group, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) GroupByID(_ context.Context, _ ULID) (r0 *Group, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) GroupByExternalIDInOrg(_ context.Context, _ ULID, _ string) (r0 *Group, err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) UpdateGroup(_ context.Context, _ Group) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) DeleteGroup(_ context.Context, _ ULID) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) SetGroupMembers(_ context.Context, _ ULID, _ []ULID) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) AddGroupMembers(_ context.Context, _ ULID, _ []ULID) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) RemoveGroupMembers(_ context.Context, _ ULID, _ []ULID) (err error) {
	err = missingCapability("SCIMStorage")
	return
}

func (unsupportedSCIMStorage) GroupMembers(_ context.Context, _ ULID) (r0 []ULID, err error) {
	err = missingCapability("SCIMStorage")
	return
}

// unsupportedRBACStorage satisfies RBACStorage with methods that report ErrStorageMissingCapability.
type unsupportedRBACStorage struct{}

func (unsupportedRBACStorage) InsertPermission(_ context.Context, _ Permission) (r0 Permission, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) PermissionByName(_ context.Context, _ string) (r0 *Permission, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) ListPermissions(_ context.Context) (r0 []Permission, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) InsertRole(_ context.Context, _ Role) (r0 Role, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) UpdateRoleRow(_ context.Context, _ Role) (r0 Role, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) DeleteRole(_ context.Context, _ ULID) (err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) RoleByID(_ context.Context, _ ULID) (r0 *Role, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) RoleByOrgAndName(_ context.Context, _ *ULID, _ string) (r0 *Role, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) RolesByOrganization(_ context.Context, _ *ULID) (r0 []Role, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) SetRolePermissions(_ context.Context, _ ULID, _ []ULID) (err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) PermissionsByRole(_ context.Context, _ ULID) (r0 []string, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) GrantUserRole(_ context.Context, _ UserRole) (err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) RevokeUserRole(_ context.Context, _ ULID, _ ULID) (err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) RolesForUser(_ context.Context, _ ULID, _ *ULID) (r0 []Role, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) PermissionsForUser(_ context.Context, _ ULID, _ *ULID) (r0 []string, err error) {
	err = missingCapability("RBACStorage")
	return
}

func (unsupportedRBACStorage) CountUsersWithPermissionInOrg(_ context.Context, _ ULID, _ string) (r0 int, err error) {
	err = missingCapability("RBACStorage")
	return
}

// unsupportedAuditStorage satisfies AuditStorage with methods that report ErrStorageMissingCapability.
type unsupportedAuditStorage struct{}

func (unsupportedAuditStorage) InsertAuditEvents(_ context.Context, _ []AuditEvent) (err error) {
	err = missingCapability("AuditStorage")
	return
}

func (unsupportedAuditStorage) QueryAuditEvents(_ context.Context, _ AuditQuery) (r0 []AuditEvent, r1 string, err error) {
	err = missingCapability("AuditStorage")
	return
}
