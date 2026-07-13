package rbac_test

import (
	"context"
	"errors"
	"testing"

	"github.com/glincker/theauth-go"
	internalulid "github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
)

type rbacFixture struct {
	ctx    context.Context
	auth   *theauth.TheAuth
	store  *memory.Store
	orgID  theauth.ULID
	userID theauth.ULID
	roles  map[string]theauth.Role
}

func newRBACFixture(t *testing.T) rbacFixture {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store,
		BaseURL: "https://example.test",
		RBAC:    &theauth.RBACConfig{},
		Audit:   &theauth.AuditConfig{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	ctx := context.Background()
	orgID := internalulid.New()
	if _, err := store.InsertOrganization(ctx, theauth.Organization{ID: orgID, Name: "Acme", Slug: "acme"}); err != nil {
		t.Fatalf("InsertOrganization: %v", err)
	}
	if err := a.SeedOrganizationRoles(ctx, orgID); err != nil {
		t.Fatalf("SeedOrganizationRoles: %v", err)
	}
	user := theauth.User{ID: internalulid.New(), Email: "user@example.test"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.UpsertOrganizationMember(ctx, theauth.OrganizationMember{OrganizationID: orgID, UserID: user.ID, Role: theauth.OrgRoleMember}); err != nil {
		t.Fatalf("UpsertOrganizationMember: %v", err)
	}
	orgIDCp := orgID
	roleList, err := store.RolesByOrganization(ctx, &orgIDCp)
	if err != nil {
		t.Fatalf("RolesByOrganization: %v", err)
	}
	byName := map[string]theauth.Role{}
	for _, r := range roleList {
		byName[r.Name] = r
	}
	return rbacFixture{ctx: ctx, auth: a, store: store, orgID: orgID, userID: user.ID, roles: byName}
}

func TestPermissionMatrix(t *testing.T) {
	fx := newRBACFixture(t)
	cases := []struct {
		role   string
		perm   string
		expect bool
	}{
		{theauth.OrgRoleOwner, theauth.PermissionBillingRead, true},
		{theauth.OrgRoleOwner, theauth.PermissionBillingAdmin, true},
		{theauth.OrgRoleOwner, theauth.PermissionUsersAdmin, true},
		{theauth.OrgRoleOwner, theauth.PermissionAuditRead, true},
		{theauth.OrgRoleAdmin, theauth.PermissionBillingRead, true},
		{theauth.OrgRoleAdmin, theauth.PermissionBillingAdmin, false},
		{theauth.OrgRoleAdmin, theauth.PermissionUsersAdmin, true},
		{theauth.OrgRoleMember, theauth.PermissionUsersRead, true},
		{theauth.OrgRoleMember, theauth.PermissionAuditRead, true},
		{theauth.OrgRoleMember, theauth.PermissionBillingRead, false},
		{theauth.OrgRoleMember, theauth.PermissionUsersAdmin, false},
	}
	actorID := internalulid.New()
	orgIDCp := fx.orgID
	for _, c := range cases {
		t.Run(c.role+"/"+c.perm, func(t *testing.T) {
			role, ok := fx.roles[c.role]
			if !ok {
				t.Fatalf("role %q missing", c.role)
			}
			if err := fx.auth.GrantRole(fx.ctx, actorID, fx.userID, role.ID); err != nil {
				t.Fatalf("GrantRole: %v", err)
			}
			has, err := fx.auth.HasPermission(fx.ctx, fx.userID, &orgIDCp, c.perm)
			if err != nil {
				t.Fatalf("HasPermission: %v", err)
			}
			if has != c.expect {
				t.Fatalf("role=%s perm=%s want=%v got=%v", c.role, c.perm, c.expect, has)
			}
			if err := fx.auth.RevokeRole(fx.ctx, actorID, fx.userID, role.ID); err != nil {
				t.Fatalf("RevokeRole: %v", err)
			}
		})
	}
}

func TestPermissionMatrixSuperAdminBypass(t *testing.T) {
	fx := newRBACFixture(t)
	sysRole := theauth.Role{
		ID:   internalulid.New(),
		Name: theauth.SystemRoleSuperAdmin,
	}
	if _, err := fx.store.InsertRole(fx.ctx, sysRole); err != nil {
		t.Fatalf("InsertRole: %v", err)
	}
	if err := fx.store.GrantUserRole(fx.ctx, theauth.UserRole{UserID: fx.userID, RoleID: sysRole.ID}); err != nil {
		t.Fatalf("GrantUserRole: %v", err)
	}
	orgIDCp := fx.orgID
	for _, p := range []string{
		theauth.PermissionBillingAdmin,
		theauth.PermissionUsersAdmin,
		theauth.PermissionAuditRead,
	} {
		got, err := fx.auth.HasPermission(fx.ctx, fx.userID, &orgIDCp, p)
		if err != nil {
			t.Fatalf("HasPermission: %v", err)
		}
		if !got {
			t.Fatalf("super_admin should grant %s", p)
		}
	}
}

func TestPermissionMatrixNoRoleDenies(t *testing.T) {
	fx := newRBACFixture(t)
	orgIDCp := fx.orgID
	for _, p := range []string{
		theauth.PermissionBillingRead,
		theauth.PermissionUsersAdmin,
		theauth.PermissionAuditRead,
	} {
		got, err := fx.auth.HasPermission(fx.ctx, fx.userID, &orgIDCp, p)
		if err != nil {
			t.Fatalf("HasPermission: %v", err)
		}
		if got {
			t.Fatalf("user with no roles should not have %s", p)
		}
	}
}

func TestPermissionMatrixUnionOfRoles(t *testing.T) {
	fx := newRBACFixture(t)
	orgIDCp := fx.orgID
	if err := fx.auth.GrantRole(fx.ctx, fx.userID, fx.userID, fx.roles[theauth.OrgRoleMember].ID); err != nil {
		t.Fatalf("grant member: %v", err)
	}
	if err := fx.auth.GrantRole(fx.ctx, fx.userID, fx.userID, fx.roles[theauth.OrgRoleAdmin].ID); err != nil {
		t.Fatalf("grant admin: %v", err)
	}
	got, err := fx.auth.HasPermission(fx.ctx, fx.userID, &orgIDCp, theauth.PermissionUsersAdmin)
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}
	if !got {
		t.Fatal("union of member+admin should grant users:admin")
	}
}

func TestPermissionMatrixOrgIsolation(t *testing.T) {
	fx := newRBACFixture(t)
	otherOrgID := internalulid.New()
	if _, err := fx.store.InsertOrganization(fx.ctx, theauth.Organization{ID: otherOrgID, Name: "Other", Slug: "other"}); err != nil {
		t.Fatalf("insert other org: %v", err)
	}
	if err := fx.auth.SeedOrganizationRoles(fx.ctx, otherOrgID); err != nil {
		t.Fatalf("seed other org: %v", err)
	}
	otherOrgIDCp := otherOrgID
	otherRoles, _ := fx.store.RolesByOrganization(fx.ctx, &otherOrgIDCp)
	var otherOwner theauth.Role
	for _, r := range otherRoles {
		if r.Name == theauth.OrgRoleOwner {
			otherOwner = r
		}
	}
	if err := fx.store.GrantUserRole(fx.ctx, theauth.UserRole{UserID: fx.userID, RoleID: otherOwner.ID}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	// Owner of OTHER org should have billing:admin in OTHER org but NOT in original.
	got, err := fx.auth.HasPermission(fx.ctx, fx.userID, &otherOrgIDCp, theauth.PermissionBillingAdmin)
	if err != nil {
		t.Fatalf("HasPermission other: %v", err)
	}
	if !got {
		t.Fatal("owner in other org should hold billing:admin in other org")
	}
	origOrgIDCp := fx.orgID
	got2, err := fx.auth.HasPermission(fx.ctx, fx.userID, &origOrgIDCp, theauth.PermissionBillingAdmin)
	if err != nil {
		t.Fatalf("HasPermission orig: %v", err)
	}
	if got2 {
		t.Fatal("owner-elsewhere should not have billing:admin in original org")
	}
}

func TestCreateRoleRejectsUnknownPermission(t *testing.T) {
	fx := newRBACFixture(t)
	_, err := fx.auth.CreateRole(fx.ctx, fx.orgID, "custom", "test", []string{"not:a:real:permission"})
	if err == nil {
		t.Fatal("expected error for unknown permission")
	}
	if !errors.Is(err, theauth.ErrUnknownPermission) {
		t.Fatalf("expected ErrUnknownPermission, got %v", err)
	}
}

func TestSeedOrganizationRolesIdempotent(t *testing.T) {
	fx := newRBACFixture(t)
	if err := fx.auth.SeedOrganizationRoles(fx.ctx, fx.orgID); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	orgIDCp := fx.orgID
	roleList, err := fx.store.RolesByOrganization(fx.ctx, &orgIDCp)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(roleList) != 3 {
		t.Fatalf("expected 3 default roles, got %d", len(roleList))
	}
}

func TestSuperAdminNotGrantable(t *testing.T) {
	fx := newRBACFixture(t)
	sysRole := theauth.Role{ID: internalulid.New(), Name: theauth.SystemRoleSuperAdmin}
	if _, err := fx.store.InsertRole(fx.ctx, sysRole); err != nil {
		t.Fatalf("InsertRole: %v", err)
	}
	other := internalulid.New()
	err := fx.auth.GrantRole(fx.ctx, fx.userID, other, sysRole.ID)
	if !errors.Is(err, theauth.ErrForbidden) {
		t.Fatalf("expected ErrForbidden when granting super_admin, got %v", err)
	}
}

func TestRevokeRoleUnknownRole(t *testing.T) {
	fx := newRBACFixture(t)
	actor := internalulid.New()
	err := fx.auth.RevokeRole(fx.ctx, actor, fx.userID, internalulid.New())
	if !errors.Is(err, theauth.ErrStorageNotFound) {
		t.Fatalf("expected ErrStorageNotFound, got %v", err)
	}
}

func TestUpdateRoleUnknownRole(t *testing.T) {
	fx := newRBACFixture(t)
	_, err := fx.auth.UpdateRole(fx.ctx, internalulid.New(), "new-name", "desc", nil)
	if !errors.Is(err, theauth.ErrStorageNotFound) {
		t.Fatalf("expected ErrStorageNotFound, got %v", err)
	}
}

func TestDeleteRoleUnknownRole(t *testing.T) {
	fx := newRBACFixture(t)
	err := fx.auth.DeleteRole(fx.ctx, internalulid.New())
	if !errors.Is(err, theauth.ErrStorageNotFound) {
		t.Fatalf("expected ErrStorageNotFound, got %v", err)
	}
}

func TestDeleteRoleRemovesCustomRole(t *testing.T) {
	fx := newRBACFixture(t)
	role, err := fx.auth.CreateRole(fx.ctx, fx.orgID, "custom-readonly", "read only", []string{theauth.PermissionUsersRead})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := fx.auth.DeleteRole(fx.ctx, role.ID); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	got, err := fx.store.RoleByID(fx.ctx, role.ID)
	if !errors.Is(err, theauth.ErrStorageNotFound) {
		t.Fatalf("expected ErrStorageNotFound after delete, got err=%v", err)
	}
	if got != nil {
		t.Fatalf("expected role to be gone after DeleteRole, got %+v", got)
	}
}

func TestDeleteRoleBlockedWhenSoleUsersAdminGrantor(t *testing.T) {
	fx := newRBACFixture(t)
	actor := internalulid.New()
	adminRole := fx.roles[theauth.OrgRoleAdmin]
	if err := fx.auth.GrantRole(fx.ctx, actor, fx.userID, adminRole.ID); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	err := fx.auth.DeleteRole(fx.ctx, adminRole.ID)
	if !errors.Is(err, theauth.ErrRoleInUse) {
		t.Fatalf("expected ErrRoleInUse, got %v", err)
	}
}
