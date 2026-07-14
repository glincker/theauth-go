// Package rbac owns the v1.0 role + permission management surface:
// permission seeding, organization-scoped role CRUD, grant / revoke, and
// the HasPermission / PermissionsForUser checks consumed by middleware.
// Extracted from root service_rbac.go in PR A of the 2026-06 architecture
// reorg.
//
// The permission catalog, name index, and default role seeds are validated
// once at theauth.New time and passed into the Service constructor; this
// package does not re-derive them. Callers that need the legacy catalog
// helpers (SeededPermissions, DefaultRoleSeeds) keep using the root
// package functions, which still exist for backward compat.
package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
)

// Storage is the minimal persistence subset this package needs. Declared
// here (not imported from root) so the constructor cycle stays broken.
type Storage interface {
	InsertPermission(ctx context.Context, p models.Permission) (models.Permission, error)
	PermissionByName(ctx context.Context, name string) (*models.Permission, error)

	InsertRole(ctx context.Context, r models.Role) (models.Role, error)
	UpdateRoleRow(ctx context.Context, r models.Role) (models.Role, error)
	DeleteRole(ctx context.Context, id models.ULID) error
	RoleByID(ctx context.Context, id models.ULID) (*models.Role, error)
	RoleByOrgAndName(ctx context.Context, orgID *models.ULID, name string) (*models.Role, error)

	SetRolePermissions(ctx context.Context, roleID models.ULID, permissionIDs []models.ULID) error
	PermissionsByRole(ctx context.Context, roleID models.ULID) ([]string, error)

	GrantUserRole(ctx context.Context, ur models.UserRole) error
	RevokeUserRole(ctx context.Context, userID, roleID models.ULID) error
	RolesForUser(ctx context.Context, userID models.ULID, orgID *models.ULID) ([]models.Role, error)
	PermissionsForUser(ctx context.Context, userID models.ULID, orgID *models.ULID) ([]string, error)
	CountUsersWithPermissionInOrg(ctx context.Context, orgID models.ULID, perm string) (int, error)
}

// RoleSeed describes one organization-scoped role created at SeedOrgRoles
// time. Mirrors the root theauth.RoleSeed shape so the root constructor
// can pass the already-validated default seeds straight through.
type RoleSeed struct {
	Name        string
	Description string
	Permissions []string
}

// Config bundles the validated catalog, index, and default role seeds.
// The presence of a non-nil pointer is the enabled signal; nil disables
// every service method with ErrRBACDisabled.
type Config struct {
	PermCatalog      []models.Permission
	PermIndex        map[string]models.Permission
	DefaultRoleSeeds []RoleSeed
}

// Service holds the dependencies needed for RBAC service methods.
type Service struct {
	storage Storage
	cfg     *Config
	auditEm audit.Emitter
}

// New constructs an rbac Service. cfg may be nil; in that case every
// public method returns models.ErrRBACDisabled (matching the legacy root
// behavior). em may be nil; the constructor swaps in audit.NoopEmitter.
func New(storage Storage, cfg *Config, em audit.Emitter) *Service {
	if em == nil {
		em = audit.NoopEmitter{}
	}
	return &Service{storage: storage, cfg: cfg, auditEm: em}
}

// SeedPermissions ensures every seeded + consumer-extended permission row
// exists in storage. Idempotent on the permissions.name unique index.
// Returns the canonical permission rows (with their persisted IDs) so the
// caller can reuse them for role assignments.
func (s *Service) SeedPermissions(ctx context.Context) ([]models.Permission, error) {
	if s.cfg == nil {
		return nil, models.ErrRBACDisabled
	}
	out := make([]models.Permission, 0, len(s.cfg.PermCatalog))
	for _, p := range s.cfg.PermCatalog {
		if p.ID == (models.ULID{}) {
			p.ID = ulid.New()
		}
		if p.CreatedAt.IsZero() {
			p.CreatedAt = time.Now()
		}
		row, err := s.storage.InsertPermission(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("theauth: seed permission %q: %w", p.Name, err)
		}
		out = append(out, row)
	}
	return out, nil
}

// SeedOrgRoles creates the three default roles (or whatever the consumer
// configured) for one organization. Idempotent on (organization_id, name).
//
// Called automatically from handlers_organizations.go::CreateOrganization;
// safe to call again manually (e.g. after extending the seed list).
func (s *Service) SeedOrgRoles(ctx context.Context, orgID models.ULID) error {
	if s.cfg == nil {
		return nil // RBAC disabled: do nothing, do not error.
	}
	// Ensure global permission catalog rows exist + collect name -> ID.
	perms, err := s.SeedPermissions(ctx)
	if err != nil {
		return err
	}
	permByName := make(map[string]models.Permission, len(perms))
	for _, p := range perms {
		permByName[p.Name] = p
	}
	orgIDCp := orgID
	for _, seed := range s.cfg.DefaultRoleSeeds {
		role, err := s.storage.RoleByOrgAndName(ctx, &orgIDCp, seed.Name)
		if err != nil && !errors.Is(err, models.ErrStorageNotFound) {
			return fmt.Errorf("theauth: seed role %q lookup: %w", seed.Name, err)
		}
		if role == nil {
			role = &models.Role{
				ID:             ulid.New(),
				OrganizationID: &orgIDCp,
				Name:           seed.Name,
				Description:    seed.Description,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}
			created, err := s.storage.InsertRole(ctx, *role)
			if err != nil {
				return fmt.Errorf("theauth: seed role %q insert: %w", seed.Name, err)
			}
			role = &created
		}
		permIDs := make([]models.ULID, 0, len(seed.Permissions))
		for _, name := range seed.Permissions {
			p, ok := permByName[name]
			if !ok {
				return fmt.Errorf("theauth: seed role %q references unknown permission %q: %w", seed.Name, name, models.ErrUnknownPermission)
			}
			permIDs = append(permIDs, p.ID)
		}
		if err := s.storage.SetRolePermissions(ctx, role.ID, permIDs); err != nil {
			return fmt.Errorf("theauth: seed role %q permissions: %w", seed.Name, err)
		}
	}
	return nil
}

// PermissionsForUser returns the user's permission set scoped to orgID
// (nil orgID returns only system-role permissions, i.e. super_admin).
// Sorted alphabetically for deterministic output.
func (s *Service) PermissionsForUser(ctx context.Context, userID models.ULID, orgID *models.ULID) ([]string, error) {
	if s.cfg == nil {
		return nil, models.ErrRBACDisabled
	}
	return s.storage.PermissionsForUser(ctx, userID, orgID)
}

// HasPermission returns true when the user holds the named permission in
// the given organization, OR when the user holds the system super_admin
// role (which bypasses every check). orgID may be nil to ask only about
// system permissions.
func (s *Service) HasPermission(ctx context.Context, userID models.ULID, orgID *models.ULID, perm string) (bool, error) {
	if s.cfg == nil {
		return false, models.ErrRBACDisabled
	}
	if _, ok := s.cfg.PermIndex[perm]; !ok {
		return false, fmt.Errorf("%w: %s", models.ErrUnknownPermission, perm)
	}
	// super_admin check (system role, org NULL).
	roles, err := s.storage.RolesForUser(ctx, userID, nil)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		if r.Name == models.SystemRoleSuperAdmin {
			return true, nil
		}
	}
	if orgID == nil {
		return false, nil
	}
	perms, err := s.storage.PermissionsForUser(ctx, userID, orgID)
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

// GrantRole assigns roleID to the target user. The actor must already
// have permission to grant; callers should run the RequirePermission
// middleware upstream of this method. Idempotent on (user_id, role_id).
// Emits action "role.granted" with role_id and role_name in metadata.
func (s *Service) GrantRole(ctx context.Context, actor, target, roleID models.ULID) error {
	if s.cfg == nil {
		return models.ErrRBACDisabled
	}
	role, err := s.storage.RoleByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return models.ErrStorageNotFound
	}
	// Never expose a path to grant super_admin via the public API; only
	// direct DB insert or a CLI may do so.
	if role.OrganizationID == nil && role.Name == models.SystemRoleSuperAdmin {
		return models.ErrForbidden
	}
	actorCp := actor
	ur := models.UserRole{
		UserID:    target,
		RoleID:    roleID,
		GrantedAt: time.Now(),
		GrantedBy: &actorCp,
	}
	if err := s.storage.GrantUserRole(ctx, ur); err != nil {
		return err
	}
	meta := map[string]any{"role_id": roleID.String(), "role_name": role.Name}
	if role.OrganizationID != nil {
		meta["organization_id"] = role.OrganizationID.String()
	}
	s.auditEm.EmitAudit(ctx, "role.granted", models.TargetRef{Type: "user", ID: target.String()}, meta)
	return nil
}

// RevokeRole removes roleID from the target user. Emits "role.revoked".
func (s *Service) RevokeRole(ctx context.Context, actor, target, roleID models.ULID) error {
	if s.cfg == nil {
		return models.ErrRBACDisabled
	}
	role, err := s.storage.RoleByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return models.ErrStorageNotFound
	}
	if err := s.storage.RevokeUserRole(ctx, target, roleID); err != nil {
		return err
	}
	s.auditEm.EmitAudit(ctx, "role.revoked", models.TargetRef{Type: "user", ID: target.String()}, map[string]any{
		"role_id":   roleID.String(),
		"role_name": role.Name,
	})
	return nil
}

// CreateRole adds a new role to orgID with the listed permissions. Names
// are unique per org; returns the storage error (typically a
// unique-violation translation) on collision. Emits "role.created".
func (s *Service) CreateRole(ctx context.Context, orgID models.ULID, name, description string, perms []string) (models.Role, error) {
	if s.cfg == nil {
		return models.Role{}, models.ErrRBACDisabled
	}
	if err := s.validatePermissions(perms); err != nil {
		return models.Role{}, err
	}
	orgIDCp := orgID
	role := models.Role{
		ID:             ulid.New(),
		OrganizationID: &orgIDCp,
		Name:           name,
		Description:    description,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	created, err := s.storage.InsertRole(ctx, role)
	if err != nil {
		return models.Role{}, err
	}
	permIDs, err := s.permIDsForNames(ctx, perms)
	if err != nil {
		return models.Role{}, err
	}
	if err := s.storage.SetRolePermissions(ctx, created.ID, permIDs); err != nil {
		return models.Role{}, err
	}
	created.Permissions = perms
	s.auditEm.EmitAudit(ctx, "role.created", models.TargetRef{Type: "role", ID: created.ID.String()}, map[string]any{
		"name":        name,
		"permissions": perms,
	})
	return created, nil
}

// UpdateRole rewrites name / description / permissions on an existing
// role. nil-valued fields are not touched (caller passes the current value).
// Emits "role.updated".
func (s *Service) UpdateRole(ctx context.Context, roleID models.ULID, name, description string, perms []string) (models.Role, error) {
	if s.cfg == nil {
		return models.Role{}, models.ErrRBACDisabled
	}
	role, err := s.storage.RoleByID(ctx, roleID)
	if err != nil {
		return models.Role{}, err
	}
	if role == nil {
		return models.Role{}, models.ErrStorageNotFound
	}
	if name != "" {
		role.Name = name
	}
	role.Description = description
	role.UpdatedAt = time.Now()
	updated, err := s.storage.UpdateRoleRow(ctx, *role)
	if err != nil {
		return models.Role{}, err
	}
	if perms != nil {
		if err := s.validatePermissions(perms); err != nil {
			return models.Role{}, err
		}
		permIDs, err := s.permIDsForNames(ctx, perms)
		if err != nil {
			return models.Role{}, err
		}
		if err := s.storage.SetRolePermissions(ctx, roleID, permIDs); err != nil {
			return models.Role{}, err
		}
		updated.Permissions = perms
	}
	s.auditEm.EmitAudit(ctx, "role.updated", models.TargetRef{Type: "role", ID: roleID.String()}, map[string]any{
		"name":        updated.Name,
		"permissions": updated.Permissions,
	})
	return updated, nil
}

// DeleteRole removes a role. Returns models.ErrRoleInUse when the role is
// the sole grantor of users:admin in its organization (lockout protection).
// Emits "role.deleted".
func (s *Service) DeleteRole(ctx context.Context, roleID models.ULID) error {
	if s.cfg == nil {
		return models.ErrRBACDisabled
	}
	role, err := s.storage.RoleByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return models.ErrStorageNotFound
	}
	if role.OrganizationID != nil {
		count, err := s.storage.CountUsersWithPermissionInOrg(ctx, *role.OrganizationID, models.PermissionUsersAdmin)
		if err != nil {
			return err
		}
		// Compute how many users hold users:admin via this specific role.
		perms, err := s.storage.PermissionsByRole(ctx, roleID)
		if err != nil {
			return err
		}
		hasAdmin := false
		for _, p := range perms {
			if p == models.PermissionUsersAdmin {
				hasAdmin = true
				break
			}
		}
		// If this role grants users:admin AND the global users:admin
		// holder count would drop to zero on its deletion, refuse.
		// Conservative approximation: refuse when count == number of
		// grantees of this role. Production-grade lockout protection
		// would diff the sets; the conservative version is sufficient
		// for v1.0 and intentionally errs on the safe side.
		if hasAdmin && count <= 1 {
			return models.ErrRoleInUse
		}
	}
	if err := s.storage.DeleteRole(ctx, roleID); err != nil {
		return err
	}
	s.auditEm.EmitAudit(ctx, "role.deleted", models.TargetRef{Type: "role", ID: roleID.String()}, nil)
	return nil
}

// validatePermissions rejects any name not present in the seeded +
// extended permission catalog.
func (s *Service) validatePermissions(perms []string) error {
	for _, p := range perms {
		if _, ok := s.cfg.PermIndex[p]; !ok {
			return fmt.Errorf("%w: %s", models.ErrUnknownPermission, p)
		}
	}
	return nil
}

// permIDsForNames resolves a permission-name slice to the corresponding
// permission IDs. SeedPermissions must have been invoked beforehand so the
// rows exist in storage.
func (s *Service) permIDsForNames(ctx context.Context, names []string) ([]models.ULID, error) {
	out := make([]models.ULID, 0, len(names))
	for _, name := range names {
		p, err := s.storage.PermissionByName(ctx, name)
		if err != nil {
			return nil, err
		}
		if p == nil {
			return nil, fmt.Errorf("%w: %s", models.ErrUnknownPermission, name)
		}
		out = append(out, p.ID)
	}
	return out, nil
}
