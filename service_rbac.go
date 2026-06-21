package theauth

import (
	"context"

	internalulid "github.com/glincker/theauth-go/internal/ulid"
)

// RBAC service forwarders. PR A architecture reorg (2026-06) moved the
// implementations to internal/rbac; the exported method signatures on
// *TheAuth are unchanged (SeedPermissions / SeedOrganizationRoles /
// PermissionsForUser / HasPermission / GrantRole / RevokeRole /
// CreateRole / UpdateRole / DeleteRole) so handlers and consumer code
// keep compiling.
//
// newULID stays defined here (lowercase, package-internal) because
// service_audit.go and handlers_admin.go still call it. The internal rbac
// package uses internal/ulid.New directly.

// newULID returns a fresh ULID seeded with crypto/rand. Mirrors
// internal/ulid.New so callers in this package do not need a second import.
func newULID() ULID {
	return internalulid.New()
}

// SeedPermissions ensures every seeded + consumer-extended permission row
// exists in storage. Idempotent on the permissions.name unique index.
// Returns the canonical permission rows (with their persisted IDs) so the
// caller can reuse them for role assignments.
//
// SeedPermissions runs lazily on first SeedOrganizationRoles / CreateRole
// invocation; consumers wanting eager seeding at app start may call it
// directly from their bootstrap.
func (a *TheAuth) SeedPermissions(ctx context.Context) ([]Permission, error) {
	return a.rbacSvc.SeedPermissions(ctx)
}

// SeedOrganizationRoles creates the three default roles (or whatever the
// consumer configured) for one organization. Idempotent on
// (organization_id, name); existing roles keep their IDs and have their
// permission set reconciled against the seed.
//
// Called automatically from handlers_organizations.go::CreateOrganization;
// safe to call again manually (e.g. after extending the seed list).
func (a *TheAuth) SeedOrganizationRoles(ctx context.Context, orgID ULID) error {
	return a.rbacSvc.SeedOrgRoles(ctx, orgID)
}

// PermissionsForUser returns the user's permission set scoped to orgID
// (nil orgID returns only system-role permissions, i.e. super_admin).
// Sorted alphabetically for deterministic output.
func (a *TheAuth) PermissionsForUser(ctx context.Context, userID ULID, orgID *ULID) ([]string, error) {
	return a.rbacSvc.PermissionsForUser(ctx, userID, orgID)
}

// HasPermission returns true when the user holds the named permission in
// the given organization, OR when the user holds the system super_admin
// role (which bypasses every check). orgID may be nil to ask only about
// system permissions.
func (a *TheAuth) HasPermission(ctx context.Context, userID ULID, orgID *ULID, perm string) (bool, error) {
	return a.rbacSvc.HasPermission(ctx, userID, orgID, perm)
}

// GrantRole assigns roleID to the target user. The actor must already
// have permission to grant; callers should run the RequirePermission
// middleware upstream of this method. Idempotent on (user_id, role_id).
// Emits action "role.granted" with role_id and role_name in metadata.
func (a *TheAuth) GrantRole(ctx context.Context, actor, target, roleID ULID) error {
	return a.rbacSvc.GrantRole(ctx, actor, target, roleID)
}

// RevokeRole removes roleID from the target user. Emits "role.revoked".
func (a *TheAuth) RevokeRole(ctx context.Context, actor, target, roleID ULID) error {
	return a.rbacSvc.RevokeRole(ctx, actor, target, roleID)
}

// CreateRole adds a new role to orgID with the listed permissions. Names
// are unique per org; returns the storage error (typically a
// unique-violation translation) on collision. Emits "role.created".
func (a *TheAuth) CreateRole(ctx context.Context, orgID ULID, name, description string, perms []string) (Role, error) {
	return a.rbacSvc.CreateRole(ctx, orgID, name, description, perms)
}

// UpdateRole rewrites name / description / permissions on an existing
// role. nil-valued fields are not touched (caller passes the current value).
// Emits "role.updated".
func (a *TheAuth) UpdateRole(ctx context.Context, roleID ULID, name, description string, perms []string) (Role, error) {
	return a.rbacSvc.UpdateRole(ctx, roleID, name, description, perms)
}

// DeleteRole removes a role. Returns ErrRoleInUse when the role is the
// sole grantor of users:admin in its organization (lockout protection).
// Emits "role.deleted".
func (a *TheAuth) DeleteRole(ctx context.Context, roleID ULID) error {
	return a.rbacSvc.DeleteRole(ctx, roleID)
}
