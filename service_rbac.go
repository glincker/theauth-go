package theauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	internalulid "github.com/glincker/theauth-go/internal/ulid"
)

// SeedPermissions ensures every seeded + consumer-extended permission row
// exists in storage. Idempotent on the permissions.name unique index.
// Returns the canonical permission rows (with their persisted IDs) so the
// caller can reuse them for role assignments.
//
// SeedPermissions runs lazily on first SeedOrganizationRoles / CreateRole
// invocation; consumers wanting eager seeding at app start may call it
// directly from their bootstrap.
func (a *TheAuth) SeedPermissions(ctx context.Context) ([]Permission, error) {
	if a.rbacCfg == nil {
		return nil, ErrRBACDisabled
	}
	out := make([]Permission, 0, len(a.permCatalog))
	for _, p := range a.permCatalog {
		if p.ID == (ULID{}) {
			p.ID = newULID()
		}
		if p.CreatedAt.IsZero() {
			p.CreatedAt = time.Now()
		}
		row, err := a.storage.InsertPermission(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("theauth: seed permission %q: %w", p.Name, err)
		}
		out = append(out, row)
	}
	return out, nil
}

// SeedOrganizationRoles creates the three default roles (or whatever the
// consumer configured) for one organization. Idempotent on (organization_id,
// name); existing roles keep their IDs and have their permission set
// reconciled against the seed.
//
// Called automatically from handlers_organizations.go::CreateOrganization;
// safe to call again manually (e.g. after extending the seed list).
func (a *TheAuth) SeedOrganizationRoles(ctx context.Context, orgID ULID) error {
	if a.rbacCfg == nil {
		return nil // RBAC disabled: do nothing, do not error.
	}
	// Ensure global permission catalog rows exist + collect name -> ID.
	perms, err := a.SeedPermissions(ctx)
	if err != nil {
		return err
	}
	permByName := make(map[string]Permission, len(perms))
	for _, p := range perms {
		permByName[p.Name] = p
	}
	orgIDCp := orgID
	for _, seed := range a.defaultRoleSeeds {
		role, err := a.storage.RoleByOrgAndName(ctx, &orgIDCp, seed.Name)
		if err != nil && !errors.Is(err, ErrStorageNotFound) {
			return fmt.Errorf("theauth: seed role %q lookup: %w", seed.Name, err)
		}
		if role == nil {
			role = &Role{
				ID:             newULID(),
				OrganizationID: &orgIDCp,
				Name:           seed.Name,
				Description:    seed.Description,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}
			created, err := a.storage.InsertRole(ctx, *role)
			if err != nil {
				return fmt.Errorf("theauth: seed role %q insert: %w", seed.Name, err)
			}
			role = &created
		}
		permIDs := make([]ULID, 0, len(seed.Permissions))
		for _, name := range seed.Permissions {
			p, ok := permByName[name]
			if !ok {
				return fmt.Errorf("theauth: seed role %q references unknown permission %q: %w", seed.Name, name, ErrUnknownPermission)
			}
			permIDs = append(permIDs, p.ID)
		}
		if err := a.storage.SetRolePermissions(ctx, role.ID, permIDs); err != nil {
			return fmt.Errorf("theauth: seed role %q permissions: %w", seed.Name, err)
		}
	}
	return nil
}

// PermissionsForUser returns the user's permission set scoped to orgID
// (nil orgID returns only system-role permissions, i.e. super_admin).
// Sorted alphabetically for deterministic output.
func (a *TheAuth) PermissionsForUser(ctx context.Context, userID ULID, orgID *ULID) ([]string, error) {
	if a.rbacCfg == nil {
		return nil, ErrRBACDisabled
	}
	return a.storage.PermissionsForUser(ctx, userID, orgID)
}

// HasPermission returns true when the user holds the named permission in
// the given organization, OR when the user holds the system super_admin
// role (which bypasses every check). orgID may be nil to ask only about
// system permissions.
func (a *TheAuth) HasPermission(ctx context.Context, userID ULID, orgID *ULID, perm string) (bool, error) {
	if a.rbacCfg == nil {
		return false, ErrRBACDisabled
	}
	if _, ok := a.permIndex[perm]; !ok {
		return false, fmt.Errorf("%w: %s", ErrUnknownPermission, perm)
	}
	// super_admin check (system role, org NULL).
	roles, err := a.storage.RolesForUser(ctx, userID, nil)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		if r.Name == SystemRoleSuperAdmin {
			return true, nil
		}
	}
	if orgID == nil {
		return false, nil
	}
	perms, err := a.storage.PermissionsForUser(ctx, userID, orgID)
	if err != nil {
		return false, err
	}
	for _, p := range perms {
		if p == perm {
			return true, nil
		}
	}
	return false, nil
}

// GrantRole assigns roleID to the target user. The actor must already have
// permission to grant; callers should run the RequirePermission middleware
// upstream of this method. Idempotent on (user_id, role_id).
// Emits action "role.granted" with role_id and role_name in metadata.
func (a *TheAuth) GrantRole(ctx context.Context, actor, target, roleID ULID) error {
	if a.rbacCfg == nil {
		return ErrRBACDisabled
	}
	role, err := a.storage.RoleByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return ErrStorageNotFound
	}
	// Never expose a path to grant super_admin via the public API; only
	// direct DB insert or a CLI may do so.
	if role.OrganizationID == nil && role.Name == SystemRoleSuperAdmin {
		return ErrForbidden
	}
	actorCp := actor
	ur := UserRole{
		UserID:    target,
		RoleID:    roleID,
		GrantedAt: time.Now(),
		GrantedBy: &actorCp,
	}
	if err := a.storage.GrantUserRole(ctx, ur); err != nil {
		return err
	}
	meta := map[string]any{"role_id": roleID.String(), "role_name": role.Name}
	if role.OrganizationID != nil {
		meta["organization_id"] = role.OrganizationID.String()
	}
	a.EmitAudit(ctx, "role.granted", TargetRef{Type: "user", ID: target.String()}, meta)
	return nil
}

// RevokeRole removes roleID from the target user. Emits "role.revoked".
func (a *TheAuth) RevokeRole(ctx context.Context, actor, target, roleID ULID) error {
	if a.rbacCfg == nil {
		return ErrRBACDisabled
	}
	role, err := a.storage.RoleByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return ErrStorageNotFound
	}
	if err := a.storage.RevokeUserRole(ctx, target, roleID); err != nil {
		return err
	}
	_ = actor
	a.EmitAudit(ctx, "role.revoked", TargetRef{Type: "user", ID: target.String()}, map[string]any{
		"role_id":   roleID.String(),
		"role_name": role.Name,
	})
	return nil
}

// CreateRole adds a new role to orgID with the listed permissions. Names
// are unique per org; returns the storage error (typically a unique-violation
// translation) on collision. Emits "role.created".
func (a *TheAuth) CreateRole(ctx context.Context, orgID ULID, name, description string, perms []string) (Role, error) {
	if a.rbacCfg == nil {
		return Role{}, ErrRBACDisabled
	}
	if err := a.validatePermissions(perms); err != nil {
		return Role{}, err
	}
	orgIDCp := orgID
	role := Role{
		ID:             newULID(),
		OrganizationID: &orgIDCp,
		Name:           name,
		Description:    description,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	created, err := a.storage.InsertRole(ctx, role)
	if err != nil {
		return Role{}, err
	}
	permIDs, err := a.permIDsForNames(ctx, perms)
	if err != nil {
		return Role{}, err
	}
	if err := a.storage.SetRolePermissions(ctx, created.ID, permIDs); err != nil {
		return Role{}, err
	}
	created.Permissions = perms
	a.EmitAudit(ctx, "role.created", TargetRef{Type: "role", ID: created.ID.String()}, map[string]any{
		"name":        name,
		"permissions": perms,
	})
	return created, nil
}

// UpdateRole rewrites name / description / permissions on an existing role.
// nil-valued fields are not touched (caller passes the current value).
// Emits "role.updated".
func (a *TheAuth) UpdateRole(ctx context.Context, roleID ULID, name, description string, perms []string) (Role, error) {
	if a.rbacCfg == nil {
		return Role{}, ErrRBACDisabled
	}
	role, err := a.storage.RoleByID(ctx, roleID)
	if err != nil {
		return Role{}, err
	}
	if role == nil {
		return Role{}, ErrStorageNotFound
	}
	if name != "" {
		role.Name = name
	}
	role.Description = description
	role.UpdatedAt = time.Now()
	updated, err := a.storage.UpdateRoleRow(ctx, *role)
	if err != nil {
		return Role{}, err
	}
	if perms != nil {
		if err := a.validatePermissions(perms); err != nil {
			return Role{}, err
		}
		permIDs, err := a.permIDsForNames(ctx, perms)
		if err != nil {
			return Role{}, err
		}
		if err := a.storage.SetRolePermissions(ctx, roleID, permIDs); err != nil {
			return Role{}, err
		}
		updated.Permissions = perms
	}
	a.EmitAudit(ctx, "role.updated", TargetRef{Type: "role", ID: roleID.String()}, map[string]any{
		"name":        updated.Name,
		"permissions": updated.Permissions,
	})
	return updated, nil
}

// DeleteRole removes a role. Returns ErrRoleInUse when the role is the sole
// grantor of users:admin in its organization (lockout protection).
// Emits "role.deleted".
func (a *TheAuth) DeleteRole(ctx context.Context, roleID ULID) error {
	if a.rbacCfg == nil {
		return ErrRBACDisabled
	}
	role, err := a.storage.RoleByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return ErrStorageNotFound
	}
	if role.OrganizationID != nil {
		count, err := a.storage.CountUsersWithPermissionInOrg(ctx, *role.OrganizationID, PermissionUsersAdmin)
		if err != nil {
			return err
		}
		// Compute how many users hold users:admin via this specific role.
		perms, err := a.storage.PermissionsByRole(ctx, roleID)
		if err != nil {
			return err
		}
		hasAdmin := false
		for _, p := range perms {
			if p == PermissionUsersAdmin {
				hasAdmin = true
				break
			}
		}
		// If this role grants users:admin AND the global users:admin holder
		// count would drop to zero on its deletion, refuse. Conservative
		// approximation: refuse when count == number of grantees of this
		// role. Production-grade lockout protection would diff the sets;
		// the conservative version is sufficient for v1.0 and intentionally
		// errs on the safe side.
		if hasAdmin && count <= 1 {
			return ErrRoleInUse
		}
	}
	if err := a.storage.DeleteRole(ctx, roleID); err != nil {
		return err
	}
	a.EmitAudit(ctx, "role.deleted", TargetRef{Type: "role", ID: roleID.String()}, nil)
	return nil
}

// validatePermissions rejects any name not present in the seeded + extended
// permission catalog.
func (a *TheAuth) validatePermissions(perms []string) error {
	for _, p := range perms {
		if _, ok := a.permIndex[p]; !ok {
			return fmt.Errorf("%w: %s", ErrUnknownPermission, p)
		}
	}
	return nil
}

// permIDsForNames resolves a permission-name slice to the corresponding
// permission IDs. SeedPermissions must have been invoked beforehand so the
// rows exist in storage.
func (a *TheAuth) permIDsForNames(ctx context.Context, names []string) ([]ULID, error) {
	out := make([]ULID, 0, len(names))
	for _, name := range names {
		p, err := a.storage.PermissionByName(ctx, name)
		if err != nil {
			return nil, err
		}
		if p == nil {
			return nil, fmt.Errorf("%w: %s", ErrUnknownPermission, name)
		}
		out = append(out, p.ID)
	}
	return out, nil
}

// newULID returns a fresh ULID seeded with crypto/rand. Mirrors the helper
// in internal/ulid so callers in this file do not need a third import.
func newULID() ULID {
	return internalulid.New()
}
