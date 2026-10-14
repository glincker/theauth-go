package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// rbac_caps.go: RBACStorage over migration 0016. A nil organization means
// the system-role namespace, matched with IS so NULL compares equal.

var _ theauth.RBACStorage = (*Store)(nil)

const permCols = `id, name, description, created_at`

func scanPermission(r scanner) (theauth.Permission, error) {
	var id, name, desc string
	var created int64
	if err := r.Scan(&id, &name, &desc, &created); err != nil {
		return theauth.Permission{}, err
	}
	pid, err := parseID(id)
	if err != nil {
		return theauth.Permission{}, err
	}
	return theauth.Permission{ID: pid, Name: name, Description: desc, CreatedAt: fromMicro(created)}, nil
}

// InsertPermission is idempotent on the name: a duplicate returns the existing row.
func (s *Store) InsertPermission(ctx context.Context, p theauth.Permission) (theauth.Permission, error) {
	out, err := scanPermission(s.db.QueryRowContext(ctx, s.q(`
INSERT INTO theauth_permissions (id, name, description, created_at) VALUES (?, ?, ?, ?)
ON CONFLICT (name) DO UPDATE SET description = theauth_permissions.description
RETURNING `+permCols), idStr(p.ID), p.Name, p.Description, toMicro(orNow(p.CreatedAt))))
	if err != nil {
		return theauth.Permission{}, wrap("insert permission", err)
	}
	return out, nil
}

// PermissionByName returns the permission with the given name.
func (s *Store) PermissionByName(ctx context.Context, name string) (*theauth.Permission, error) {
	p, err := scanPermission(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+permCols+` FROM theauth_permissions WHERE name = ?`), name))
	if err != nil {
		return nil, notFoundOr("permission by name", err)
	}
	return &p, nil
}

// ListPermissions returns the catalog ordered by name.
func (s *Store) ListPermissions(ctx context.Context) ([]theauth.Permission, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+permCols+` FROM theauth_permissions ORDER BY name ASC`))
	if err != nil {
		return nil, wrap("list permissions", err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.Permission{}
	for rows.Next() {
		p, err := scanPermission(rows)
		if err != nil {
			return nil, wrap("list permissions", err)
		}
		out = append(out, p)
	}
	return out, wrap("list permissions", rows.Err())
}

const roleCols = `id, organization_id, name, description, created_at, updated_at`

func scanRole(r scanner) (theauth.Role, error) {
	var (
		id, name, desc   string
		org              sql.NullString
		created, updated int64
	)
	if err := r.Scan(&id, &org, &name, &desc, &created, &updated); err != nil {
		return theauth.Role{}, err
	}
	rid, err := parseID(id)
	if err != nil {
		return theauth.Role{}, err
	}
	oid, err := parseIDPtr(org)
	if err != nil {
		return theauth.Role{}, err
	}
	return theauth.Role{
		ID: rid, OrganizationID: oid, Name: name, Description: desc,
		CreatedAt: fromMicro(created), UpdatedAt: fromMicro(updated),
	}, nil
}

// InsertRole stores a role; names are unique within an organization and among system roles.
func (s *Store) InsertRole(ctx context.Context, r theauth.Role) (theauth.Role, error) {
	created := orNow(r.CreatedAt)
	updated := r.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	out, err := scanRole(s.db.QueryRowContext(ctx, s.q(`
INSERT INTO theauth_roles (`+roleCols+`) VALUES (?, ?, ?, ?, ?, ?) RETURNING `+roleCols),
		idStr(r.ID), idPtrStr(r.OrganizationID), r.Name, r.Description, toMicro(created), toMicro(updated)))
	if err != nil {
		return theauth.Role{}, wrap("insert role", err)
	}
	return out, nil
}

// UpdateRoleRow rewrites a role's name and description.
func (s *Store) UpdateRoleRow(ctx context.Context, r theauth.Role) (theauth.Role, error) {
	out, err := scanRole(s.db.QueryRowContext(ctx, s.q(`
UPDATE theauth_roles SET name = ?, description = ?, updated_at = ? WHERE id = ? RETURNING `+roleCols),
		r.Name, r.Description, toMicro(time.Now()), idStr(r.ID)))
	if err != nil {
		return theauth.Role{}, notFoundOr("update role", err)
	}
	return out, nil
}

// DeleteRole removes a role and, by cascade, its grants and permission links.
func (s *Store) DeleteRole(ctx context.Context, id theauth.ULID) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM theauth_roles WHERE id = ?`), idStr(id))
	if err != nil {
		return wrap("delete role", err)
	}
	return requireRows("delete role", res)
}

func (s *Store) withPermissions(ctx context.Context, r theauth.Role) (theauth.Role, error) {
	perms, err := s.PermissionsByRole(ctx, r.ID)
	if err != nil {
		return theauth.Role{}, err
	}
	r.Permissions = perms
	return r, nil
}

// RoleByID returns a role with its permission names.
func (s *Store) RoleByID(ctx context.Context, id theauth.ULID) (*theauth.Role, error) {
	r, err := scanRole(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+roleCols+` FROM theauth_roles WHERE id = ?`), idStr(id)))
	if err != nil {
		return nil, notFoundOr("role by id", err)
	}
	r, err = s.withPermissions(ctx, r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// RoleByOrgAndName returns a role by name within an organization, or among system roles when orgID is nil.
func (s *Store) RoleByOrgAndName(ctx context.Context, orgID *theauth.ULID, name string) (*theauth.Role, error) {
	r, err := scanRole(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+roleCols+` FROM theauth_roles WHERE name = ? AND organization_id IS ?`),
		name, idPtrStr(orgID)))
	if err != nil {
		return nil, notFoundOr("role by org and name", err)
	}
	r, err = s.withPermissions(ctx, r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// RolesByOrganization lists roles of one organization, or the system roles when orgID is nil.
func (s *Store) RolesByOrganization(ctx context.Context, orgID *theauth.ULID) ([]theauth.Role, error) {
	roles, err := s.queryRoles(ctx, "roles by organization",
		`SELECT `+roleCols+` FROM theauth_roles WHERE organization_id IS ? ORDER BY name ASC`, idPtrStr(orgID))
	if err != nil {
		return nil, err
	}
	for i := range roles {
		if roles[i], err = s.withPermissions(ctx, roles[i]); err != nil {
			return nil, err
		}
	}
	return roles, nil
}

func (s *Store) queryRoles(ctx context.Context, op, query string, args ...any) ([]theauth.Role, error) {
	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, wrap(op, err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.Role{}
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, wrap(op, err)
		}
		out = append(out, r)
	}
	return out, wrap(op, rows.Err())
}

// SetRolePermissions replaces a role's permission set atomically.
func (s *Store) SetRolePermissions(ctx context.Context, roleID theauth.ULID, permissionIDs []theauth.ULID) error {
	return s.inTx(ctx, "set role permissions", func(tx DBTX) error {
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM theauth_role_permissions WHERE role_id = ?`), idStr(roleID)); err != nil {
			return err
		}
		for _, pid := range permissionIDs {
			if _, err := tx.ExecContext(ctx, s.q(`
INSERT INTO theauth_role_permissions (role_id, permission_id) VALUES (?, ?) ON CONFLICT DO NOTHING`),
				idStr(roleID), idStr(pid)); err != nil {
				return err
			}
		}
		return nil
	})
}

// PermissionsByRole returns a role's permission names in order.
func (s *Store) PermissionsByRole(ctx context.Context, roleID theauth.ULID) ([]string, error) {
	return s.queryNames(ctx, "permissions by role", `
SELECT p.name FROM theauth_permissions p
JOIN theauth_role_permissions rp ON rp.permission_id = p.id
WHERE rp.role_id = ? ORDER BY p.name ASC`, idStr(roleID))
}

func (s *Store) queryNames(ctx context.Context, op, query string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, wrap(op, err)
	}
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, wrap(op, err)
		}
		out = append(out, n)
	}
	return out, wrap(op, rows.Err())
}

// GrantUserRole binds a role to a user and keeps the first grant on repeat calls.
func (s *Store) GrantUserRole(ctx context.Context, ur theauth.UserRole) error {
	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_user_roles (user_id, role_id, granted_at, granted_by) VALUES (?, ?, ?, ?)
ON CONFLICT (user_id, role_id) DO NOTHING`),
		idStr(ur.UserID), idStr(ur.RoleID), toMicro(orNow(ur.GrantedAt)), idPtrStr(ur.GrantedBy))
	return wrap("grant user role", err)
}

// RevokeUserRole removes a grant, returning ErrStorageNotFound when none existed.
func (s *Store) RevokeUserRole(ctx context.Context, userID, roleID theauth.ULID) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM theauth_user_roles WHERE user_id = ? AND role_id = ?`),
		idStr(userID), idStr(roleID))
	if err != nil {
		return wrap("revoke user role", err)
	}
	return requireRows("revoke user role", res)
}

// RolesForUser lists the user's roles in one organization, or the system roles when orgID is nil.
func (s *Store) RolesForUser(ctx context.Context, userID theauth.ULID, orgID *theauth.ULID) ([]theauth.Role, error) {
	return s.queryRoles(ctx, "roles for user", `
SELECT r.id, r.organization_id, r.name, r.description, r.created_at, r.updated_at
FROM theauth_roles r JOIN theauth_user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = ? AND r.organization_id IS ? ORDER BY r.name ASC`, idStr(userID), idPtrStr(orgID))
}

// PermissionsForUser returns the distinct permission names a user holds in one organization scope.
func (s *Store) PermissionsForUser(ctx context.Context, userID theauth.ULID, orgID *theauth.ULID) ([]string, error) {
	return s.queryNames(ctx, "permissions for user", `
SELECT DISTINCT p.name FROM theauth_permissions p
JOIN theauth_role_permissions rp ON rp.permission_id = p.id
JOIN theauth_user_roles ur ON ur.role_id = rp.role_id
JOIN theauth_roles r ON r.id = rp.role_id
WHERE ur.user_id = ? AND r.organization_id IS ? ORDER BY p.name ASC`, idStr(userID), idPtrStr(orgID))
}

// CountUsersWithPermissionInOrg counts distinct users holding perm through an organization role.
func (s *Store) CountUsersWithPermissionInOrg(ctx context.Context, orgID theauth.ULID, perm string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, s.q(`
SELECT count(DISTINCT ur.user_id) FROM theauth_user_roles ur
JOIN theauth_role_permissions rp ON rp.role_id = ur.role_id
JOIN theauth_permissions p ON p.id = rp.permission_id
JOIN theauth_roles r ON r.id = ur.role_id
WHERE p.name = ? AND r.organization_id = ?`), perm, idStr(orgID)).Scan(&n)
	return n, wrap("count users with permission", err)
}
