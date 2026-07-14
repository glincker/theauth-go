package rbac_test

import (
	"testing"

	"github.com/glincker/theauth-go"
)

// service_rbac_catalog_test.go closes the RBAC matrix gap called out in the
// 2026-06-20 reliability audit (section 2: RBAC permission matrix).
// Existing tests assert a representative subset; this file enumerates every
// permission in the seeded catalog against every default role so that a
// future addition to the catalog without updating the seeded role
// definitions will fail the table here instead of shipping silently.

// TestPermissionMatrixFullCatalog enumerates every permission from
// SeededPermissions() and asserts the owner, admin, and member roles each
// hold the documented set. The expectations mirror DefaultRoleSeeds:
//
//   - owner holds every seeded permission.
//   - admin holds every seeded permission except billing:admin.
//   - member holds users:read + audit:read only.
//
// If a new permission is added to SeededPermissions without being added to
// DefaultRoleSeeds, this test fails so the missing wiring is caught at PR
// time rather than at runtime when the first denied user files a bug.
func TestPermissionMatrixFullCatalog(t *testing.T) {
	fx := newRBACFixture(t)
	allPerms := theauth.SeededPermissions()
	if len(allPerms) == 0 {
		t.Fatal("SeededPermissions returned empty catalog")
	}

	// Expected matrix per DefaultRoleSeeds (see rbac.go:DefaultRoleSeeds).
	memberHolds := map[string]bool{
		theauth.PermissionUsersRead: true,
		theauth.PermissionAuditRead: true,
	}
	for _, p := range allPerms {
		t.Run("owner/"+p.Name, func(t *testing.T) {
			assertRoleHolds(t, fx, theauth.OrgRoleOwner, p.Name, true)
		})
		t.Run("admin/"+p.Name, func(t *testing.T) {
			// admin holds everything except billing:admin.
			want := p.Name != theauth.PermissionBillingAdmin
			assertRoleHolds(t, fx, theauth.OrgRoleAdmin, p.Name, want)
		})
		t.Run("member/"+p.Name, func(t *testing.T) {
			assertRoleHolds(t, fx, theauth.OrgRoleMember, p.Name, memberHolds[p.Name])
		})
	}
}

// assertRoleHolds grants the named default role to the fixture user, asserts
// HasPermission returns the expected boolean, then revokes the role so the
// next subtest starts from a clean slate.
func assertRoleHolds(t *testing.T, fx rbacFixture, roleName, perm string, want bool) {
	t.Helper()
	role, ok := fx.roles[roleName]
	if !ok {
		t.Fatalf("role %q not seeded", roleName)
	}
	if err := fx.auth.GrantRole(fx.ctx, fx.userID, fx.userID, role.ID); err != nil {
		t.Fatalf("GrantRole(%s): %v", roleName, err)
	}
	t.Cleanup(func() {
		_ = fx.auth.RevokeRole(fx.ctx, fx.userID, fx.userID, role.ID)
	})
	org := fx.orgID
	got, err := fx.auth.HasPermission(fx.ctx, fx.userID, &org, perm)
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}
	if got != want {
		t.Errorf("role=%s perm=%s want=%v got=%v", roleName, perm, want, got)
	}
}

// TestSeededPermissionsCoversV20PhaseAdditions guards against a regression
// where the v2.0 phase 6 permissions (agents:admin + delegations:admin) are
// removed from the seeded catalog. The audit specifically called out this
// gap: a new permission added to the catalog without being added to the
// seeded role still passes the existing matrix tests.
func TestSeededPermissionsCoversV20PhaseAdditions(t *testing.T) {
	required := map[string]bool{
		theauth.PermissionAgentsAdmin:      true,
		theauth.PermissionDelegationsAdmin: true,
	}
	for _, p := range theauth.SeededPermissions() {
		delete(required, p.Name)
	}
	if len(required) > 0 {
		t.Errorf("seeded catalog missing v2.0 phase additions: %v", required)
	}
}
