package theauth_test

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
)

// allCapabilities lists every capability interface; keep in sync with storage_caps.go.
type allCapabilities interface {
	theauth.UserStorage
	theauth.SessionStorage
	theauth.MagicLinkStorage
	theauth.PasswordStorage
	theauth.OAuthAccountStorage
	theauth.WebAuthnStorage
	theauth.TOTPStorage
	theauth.OrganizationStorage
	theauth.SAMLStorage
	theauth.SCIMStorage
	theauth.RBACStorage
	theauth.AuditStorage
}

var (
	_ theauth.Storage     = allCapabilities(nil)
	_ allCapabilities     = theauth.Storage(nil)
	_ theauth.CoreStorage = theauth.Storage(nil)
)

var frozenStorageMethods = []string{
	"AddGroupMembers",
	"ConfirmTOTPSecret",
	"ConsumeMagicLink",
	"ConsumePasswordResetToken",
	"ConsumeRecoveryCode",
	"CountUsersWithPermissionInOrg",
	"CreateMagicLink",
	"CreatePasswordResetToken",
	"CreateSession",
	"CreateSessionWithAuthLevel",
	"CreateUser",
	"DeleteGroup",
	"DeleteOAuthAccountByProvider",
	"DeleteOrganization",
	"DeleteOrganizationMember",
	"DeleteRole",
	"DeleteSAMLConnection",
	"DeleteTOTPSecret",
	"DeleteWebAuthnCredential",
	"GrantUserRole",
	"GroupByExternalIDInOrg",
	"GroupByID",
	"GroupMembers",
	"InsertAuditEvents",
	"InsertGroup",
	"InsertOrganization",
	"InsertPermission",
	"InsertRecoveryCodes",
	"InsertRole",
	"InsertSAMLConnection",
	"InsertSCIMToken",
	"InsertWebAuthnCredential",
	"ListGroupsByOrganization",
	"ListPermissions",
	"ListUsersByOrganization",
	"MarkEmailVerified",
	"MoveOAuthAccount",
	"MovePasswordHash",
	"MoveTOTPSecret",
	"MoveWebAuthnCredentials",
	"OAuthAccountByProviderUserID",
	"OAuthAccountsByUserID",
	"OrganizationByID",
	"OrganizationBySlug",
	"OrganizationMemberRole",
	"OrganizationMembersByOrg",
	"OrganizationsByUser",
	"PermissionByName",
	"PermissionsByRole",
	"PermissionsForUser",
	"QueryAuditEvents",
	"RemoveGroupMembers",
	"RevokeSCIMTokenByID",
	"RevokeSession",
	"RevokeUserRole",
	"RevokeUserSessions",
	"RoleByID",
	"RoleByOrgAndName",
	"RolesByOrganization",
	"RolesForUser",
	"SAMLConnectionByID",
	"SAMLConnectionsByOrg",
	"SAMLIdentityByConnectionAndNameID",
	"SCIMTokenByHash",
	"SCIMTokensByOrg",
	"SessionByID",
	"SessionByTokenHash",
	"SetGroupMembers",
	"SetRolePermissions",
	"SetSessionActiveOrganization",
	"SetUserPassword",
	"TOTPSecretByUserID",
	"TouchSAMLIdentityLastLogin",
	"TouchSCIMTokenLastUsed",
	"UpdateGroup",
	"UpdateOrganization",
	"UpdateRoleRow",
	"UpdateSAMLConnectionRow",
	"UpdateSessionAuthLevel",
	"UpdateUserSCIM",
	"UpdateWebAuthnBackupFlags",
	"UpdateWebAuthnSignCount",
	"UpsertOAuthAccount",
	"UpsertOrganizationMember",
	"UpsertPendingTOTPSecret",
	"UpsertSAMLIdentity",
	"UserByEmail",
	"UserByEmailWithPassword",
	"UserByExternalIDInOrg",
	"UserByID",
	"UserPasswordHashByID",
	"WebAuthnCredentialByCredentialID",
	"WebAuthnCredentialsByUserID",
}

func TestStorageMethodSetFrozen(t *testing.T) {
	typ := reflect.TypeOf((*theauth.Storage)(nil)).Elem()
	got := make([]string, 0, typ.NumMethod())
	for i := 0; i < typ.NumMethod(); i++ {
		got = append(got, typ.Method(i).Name)
	}
	sort.Strings(got)
	want := append([]string(nil), frozenStorageMethods...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Storage method set changed:\n got  %v\n want %v", got, want)
	}
}

// coreOnly hides every method of the memory store outside CoreStorage.
type coreOnly struct{ theauth.CoreStorage }

func TestNewWithCoreStorage(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*theauth.Config)
		wantErr string
	}{
		{name: "no optional features", mutate: func(*theauth.Config) {}},
		{name: "totp", mutate: func(c *theauth.Config) {
			c.TOTP = &theauth.TOTPConfig{Issuer: "x"}
			c.EncryptionKey = make([]byte, 32)
		}, wantErr: "TOTPStorage"},
		{name: "webauthn", mutate: func(c *theauth.Config) {
			c.WebAuthn = &theauth.WebAuthnConfig{RPID: "x", RPOrigins: []string{"https://x"}}
		}, wantErr: "WebAuthnStorage"},
		{name: "organizations", mutate: func(c *theauth.Config) {
			c.Organizations = &theauth.OrganizationsConfig{}
		}, wantErr: "OrganizationStorage"},
		{name: "rbac", mutate: func(c *theauth.Config) {
			c.RBAC = &theauth.RBACConfig{}
		}, wantErr: "RBACStorage"},
		{name: "audit", mutate: func(c *theauth.Config) {
			c.Audit = &theauth.AuditConfig{}
		}, wantErr: "AuditStorage"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := theauth.Config{
				CoreStorage:                 coreOnly{memory.New()},
				BaseURL:                     "http://localhost",
				SuppressSecureCookieWarning: true,
			}
			tc.mutate(&cfg)
			a, err := theauth.New(cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				defer a.Close()
				_, _, serr := theauth.SignupWithPasswordForTest(a, context.Background(), "core@x.com", validPassword)
				if serr != nil {
					t.Fatalf("signup on core storage: %v", serr)
				}
				return
			}
			if !errors.Is(err, theauth.ErrStorageMissingCapability) {
				t.Fatalf("want ErrStorageMissingCapability, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not name %s", err, tc.wantErr)
			}
		})
	}
}

func TestNewWithFullStorageSatisfiesEveryCapability(t *testing.T) {
	a, err := theauth.New(theauth.Config{
		CoreStorage:                 memory.New(),
		BaseURL:                     "http://localhost",
		SuppressSecureCookieWarning: true,
		TOTP:                        &theauth.TOTPConfig{Issuer: "x"},
		EncryptionKey:               make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.Close()
}

func TestNewStorageSelection(t *testing.T) {
	both := theauth.Config{Storage: memory.New(), CoreStorage: memory.New(), BaseURL: "http://localhost"}
	if _, err := theauth.New(both); err == nil {
		t.Fatal("expected error when both Storage and CoreStorage are set")
	}
	if _, err := theauth.New(theauth.Config{BaseURL: "http://localhost"}); err == nil {
		t.Fatal("expected error when neither Storage nor CoreStorage is set")
	}
}

func TestNewCoreStorageAuthorizationServerNeedsExtension(t *testing.T) {
	_, err := theauth.New(theauth.Config{
		CoreStorage:         coreOnly{memory.New()},
		BaseURL:             "http://localhost",
		AuthorizationServer: &theauth.AuthorizationServerConfig{Issuer: "http://localhost"},
		EncryptionKey:       make([]byte, 32),
	})
	if !errors.Is(err, theauth.ErrStorageMissingOAuthMethods) {
		t.Fatalf("want ErrStorageMissingOAuthMethods, got %v", err)
	}
}
