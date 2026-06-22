package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

func testRoles(t *testing.T, store theauth.Storage) {
	t.Helper()
	ctx := context.Background()

	uid := newID()
	if _, err := store.CreateUser(ctx, theauth.User{
		ID:        uid,
		Email:     "rbac-user@storagetest.example",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Use a global (nil org) scope so no org is required.

	t.Run("InsertPermissionIdempotent", func(t *testing.T) {
		p := theauth.Permission{
			ID:        newID(),
			Name:      "storagetest:read",
			CreatedAt: time.Now(),
		}
		p1, err := store.InsertPermission(ctx, p)
		if err != nil {
			t.Fatalf("InsertPermission: %v", err)
		}

		// Second insert on same name must return existing row.
		p2 := p
		p2.ID = newID() // different ID, same name
		p2got, err := store.InsertPermission(ctx, p2)
		if err != nil {
			t.Fatalf("InsertPermission (dup): %v", err)
		}
		if p2got.ID != p1.ID {
			t.Fatalf("idempotent insert: want ID %s, got %s", p1.ID, p2got.ID)
		}
	})

	t.Run("PermissionByName", func(t *testing.T) {
		got, err := store.PermissionByName(ctx, "storagetest:read")
		if err != nil {
			t.Fatalf("PermissionByName: %v", err)
		}
		if got.Name != "storagetest:read" {
			t.Fatalf("Name mismatch: got %q", got.Name)
		}
	})

	t.Run("PermissionByNameNotFound", func(t *testing.T) {
		if _, err := store.PermissionByName(ctx, "no-such-perm"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("ListPermissions", func(t *testing.T) {
		perms, err := store.ListPermissions(ctx)
		if err != nil {
			t.Fatalf("ListPermissions: %v", err)
		}
		found := false
		for _, p := range perms {
			if p.Name == "storagetest:read" {
				found = true
			}
		}
		if !found {
			t.Fatal("ListPermissions: storagetest:read not found in list")
		}
	})

	var roleID theauth.ULID
	var permID theauth.ULID

	t.Run("InsertRole", func(t *testing.T) {
		perm, err := store.PermissionByName(ctx, "storagetest:read")
		if err != nil {
			t.Fatalf("PermissionByName: %v", err)
		}
		permID = perm.ID

		role := theauth.Role{
			ID:        newID(),
			Name:      "storagetest-viewer",
			CreatedAt: time.Now(),
		}
		got, err := store.InsertRole(ctx, role)
		if err != nil {
			t.Fatalf("InsertRole: %v", err)
		}
		roleID = got.ID
	})

	t.Run("SetRolePermissions", func(t *testing.T) {
		if err := store.SetRolePermissions(ctx, roleID, []theauth.ULID{permID}); err != nil {
			t.Fatalf("SetRolePermissions: %v", err)
		}

		names, err := store.PermissionsByRole(ctx, roleID)
		if err != nil {
			t.Fatalf("PermissionsByRole: %v", err)
		}
		if len(names) != 1 || names[0] != "storagetest:read" {
			t.Fatalf("PermissionsByRole: got %v", names)
		}
	})

	t.Run("GrantAndRevokeUserRole", func(t *testing.T) {
		ur := theauth.UserRole{
			UserID:    uid,
			RoleID:    roleID,
			GrantedAt: time.Now(),
		}
		if err := store.GrantUserRole(ctx, ur); err != nil {
			t.Fatalf("GrantUserRole: %v", err)
		}

		roles, err := store.RolesForUser(ctx, uid, nil)
		if err != nil {
			t.Fatalf("RolesForUser: %v", err)
		}
		found := false
		for _, r := range roles {
			if r.ID == roleID {
				found = true
			}
		}
		if !found {
			t.Fatal("RolesForUser: assigned role not in list")
		}

		perms, err := store.PermissionsForUser(ctx, uid, nil)
		if err != nil {
			t.Fatalf("PermissionsForUser: %v", err)
		}
		permFound := false
		for _, p := range perms {
			if p == "storagetest:read" {
				permFound = true
			}
		}
		if !permFound {
			t.Fatal("PermissionsForUser: storagetest:read not found")
		}

		if err := store.RevokeUserRole(ctx, uid, roleID); err != nil {
			t.Fatalf("RevokeUserRole: %v", err)
		}

		roles2, err := store.RolesForUser(ctx, uid, nil)
		if err != nil {
			t.Fatalf("RolesForUser after revoke: %v", err)
		}
		for _, r := range roles2 {
			if r.ID == roleID {
				t.Fatal("role should not appear after revoke")
			}
		}
	})

	t.Run("UpdateRole", func(t *testing.T) {
		role, err := store.RoleByID(ctx, roleID)
		if err != nil {
			t.Fatalf("RoleByID: %v", err)
		}
		role.Name = "storagetest-viewer-updated"
		updated, err := store.UpdateRoleRow(ctx, *role)
		if err != nil {
			t.Fatalf("UpdateRoleRow: %v", err)
		}
		if updated.Name != "storagetest-viewer-updated" {
			t.Fatalf("Name not updated: got %q", updated.Name)
		}
	})

	t.Run("DeleteRole", func(t *testing.T) {
		if err := store.DeleteRole(ctx, roleID); err != nil {
			t.Fatalf("DeleteRole: %v", err)
		}

		if _, err := store.RoleByID(ctx, roleID); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("after delete: want ErrNotFound, got %v", err)
		}
	})

	t.Run("RoleByOrgAndName", func(t *testing.T) {
		role := theauth.Role{
			ID:        newID(),
			Name:      "storagetest-org-role",
			CreatedAt: time.Now(),
		}
		inserted, err := store.InsertRole(ctx, role)
		if err != nil {
			t.Fatalf("InsertRole: %v", err)
		}

		got, err := store.RoleByOrgAndName(ctx, nil, "storagetest-org-role")
		if err != nil {
			t.Fatalf("RoleByOrgAndName: %v", err)
		}
		if got.ID != inserted.ID {
			t.Fatalf("ID mismatch")
		}

		// Clean up.
		_ = store.DeleteRole(ctx, inserted.ID)
	})
}
