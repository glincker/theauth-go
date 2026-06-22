package mysql

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

// ---------- Permissions ----------

func (s *Store) InsertPermission(ctx context.Context, p theauth.Permission) (theauth.Permission, error) {
	created := p.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	// INSERT IGNORE is idempotent on unique name constraint.
	_, err := s.db.ExecContext(ctx, `
INSERT IGNORE INTO permissions (id, name, description, created_at)
VALUES (?, ?, ?, ?)`,
		ulidToBytes(p.ID), p.Name, p.Description, timeUTC(created),
	)
	if err != nil {
		return theauth.Permission{}, err
	}
	got, err := s.PermissionByName(ctx, p.Name)
	if err != nil {
		return theauth.Permission{}, err
	}
	return *got, nil
}

func (s *Store) PermissionByName(ctx context.Context, name string) (*theauth.Permission, error) {
	var (
		idB         []byte
		pname, desc string
		createdAt   time.Time
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, created_at FROM permissions WHERE name = ?`, name,
	).Scan(&idB, &pname, &desc, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &theauth.Permission{
		ID:          bytesToULID(idB),
		Name:        pname,
		Description: desc,
		CreatedAt:   createdAt.UTC(),
	}, nil
}

func (s *Store) ListPermissions(ctx context.Context) ([]theauth.Permission, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, description, created_at FROM permissions ORDER BY name ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.Permission
	for rows.Next() {
		var (
			idB        []byte
			name, desc string
			createdAt  time.Time
		)
		if err := rows.Scan(&idB, &name, &desc, &createdAt); err != nil {
			return nil, err
		}
		out = append(out, theauth.Permission{
			ID:          bytesToULID(idB),
			Name:        name,
			Description: desc,
			CreatedAt:   createdAt.UTC(),
		})
	}
	return out, rows.Err()
}

// ---------- Roles ----------

func (s *Store) InsertRole(ctx context.Context, r theauth.Role) (theauth.Role, error) {
	created := r.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	updated := r.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO roles (id, organization_id, name, description, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`,
		ulidToBytes(r.ID),
		ulidPtrToBytes(r.OrganizationID),
		r.Name, r.Description,
		timeUTC(created), timeUTC(updated),
	)
	if err != nil {
		return theauth.Role{}, err
	}
	got, err := s.RoleByID(ctx, r.ID)
	if err != nil {
		return theauth.Role{}, err
	}
	return *got, nil
}

func (s *Store) UpdateRoleRow(ctx context.Context, r theauth.Role) (theauth.Role, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE roles SET name = ?, description = ?, updated_at = ? WHERE id = ?`,
		r.Name, r.Description, timeUTC(time.Now()), ulidToBytes(r.ID),
	)
	if err != nil {
		return theauth.Role{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return theauth.Role{}, storage.ErrNotFound
	}
	got, err := s.RoleByID(ctx, r.ID)
	if err != nil {
		return theauth.Role{}, err
	}
	return *got, nil
}

func (s *Store) DeleteRole(ctx context.Context, id theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM roles WHERE id = ?`, ulidToBytes(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) RoleByID(ctx context.Context, id theauth.ULID) (*theauth.Role, error) {
	r, err := scanRole(s.db.QueryRowContext(ctx, `
SELECT id, organization_id, name, description, created_at, updated_at
FROM roles WHERE id = ?`, ulidToBytes(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	perms, err := s.PermissionsByRole(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	r.Permissions = perms
	return &r, nil
}

func (s *Store) RoleByOrgAndName(ctx context.Context, orgID *theauth.ULID, name string) (*theauth.Role, error) {
	var row *sql.Row
	if orgID == nil {
		row = s.db.QueryRowContext(ctx, `
SELECT id, organization_id, name, description, created_at, updated_at
FROM roles WHERE organization_id IS NULL AND name = ?`, name)
	} else {
		row = s.db.QueryRowContext(ctx, `
SELECT id, organization_id, name, description, created_at, updated_at
FROM roles WHERE organization_id = ? AND name = ?`, ulidToBytes(*orgID), name)
	}
	r, err := scanRole(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	perms, err := s.PermissionsByRole(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	r.Permissions = perms
	return &r, nil
}

func (s *Store) RolesByOrganization(ctx context.Context, orgID *theauth.ULID) ([]theauth.Role, error) {
	var rows *sql.Rows
	var err error
	if orgID == nil {
		rows, err = s.db.QueryContext(ctx, `
SELECT id, organization_id, name, description, created_at, updated_at
FROM roles WHERE organization_id IS NULL ORDER BY name ASC`)
	} else {
		rows, err = s.db.QueryContext(ctx, `
SELECT id, organization_id, name, description, created_at, updated_at
FROM roles WHERE organization_id = ? ORDER BY name ASC`, ulidToBytes(*orgID))
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		perms, err := s.PermissionsByRole(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		r.Permissions = perms
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SetRolePermissions(ctx context.Context, roleID theauth.ULID, permissionIDs []theauth.ULID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM role_permissions WHERE role_id = ?`, ulidToBytes(roleID),
	); err != nil {
		return err
	}
	for _, pid := range permissionIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)`,
			ulidToBytes(roleID), ulidToBytes(pid),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) PermissionsByRole(ctx context.Context, roleID theauth.ULID) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT p.name FROM permissions p
INNER JOIN role_permissions rp ON rp.permission_id = p.id
WHERE rp.role_id = ? ORDER BY p.name ASC`, ulidToBytes(roleID))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// ---------- User roles ----------

func (s *Store) GrantUserRole(ctx context.Context, ur theauth.UserRole) error {
	granted := ur.GrantedAt
	if granted.IsZero() {
		granted = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT IGNORE INTO user_roles (user_id, role_id, granted_at, granted_by)
VALUES (?, ?, ?, ?)`,
		ulidToBytes(ur.UserID),
		ulidToBytes(ur.RoleID),
		timeUTC(granted),
		ulidPtrToBytes(ur.GrantedBy),
	)
	return err
}

func (s *Store) RevokeUserRole(ctx context.Context, userID, roleID theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM user_roles WHERE user_id = ? AND role_id = ?`,
		ulidToBytes(userID), ulidToBytes(roleID),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) RolesForUser(ctx context.Context, userID theauth.ULID, orgID *theauth.ULID) ([]theauth.Role, error) {
	var rows *sql.Rows
	var err error
	if orgID == nil {
		rows, err = s.db.QueryContext(ctx, `
SELECT r.id, r.organization_id, r.name, r.description, r.created_at, r.updated_at
FROM roles r
INNER JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = ? AND r.organization_id IS NULL`, ulidToBytes(userID))
	} else {
		rows, err = s.db.QueryContext(ctx, `
SELECT r.id, r.organization_id, r.name, r.description, r.created_at, r.updated_at
FROM roles r
INNER JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = ? AND r.organization_id = ?`, ulidToBytes(userID), ulidToBytes(*orgID))
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) PermissionsForUser(ctx context.Context, userID theauth.ULID, orgID *theauth.ULID) ([]string, error) {
	var rows *sql.Rows
	var err error
	if orgID == nil {
		rows, err = s.db.QueryContext(ctx, `
SELECT DISTINCT p.name FROM permissions p
INNER JOIN role_permissions rp ON rp.permission_id = p.id
INNER JOIN user_roles ur ON ur.role_id = rp.role_id
INNER JOIN roles r ON r.id = ur.role_id
WHERE ur.user_id = ? AND r.organization_id IS NULL
ORDER BY p.name ASC`, ulidToBytes(userID))
	} else {
		rows, err = s.db.QueryContext(ctx, `
SELECT DISTINCT p.name FROM permissions p
INNER JOIN role_permissions rp ON rp.permission_id = p.id
INNER JOIN user_roles ur ON ur.role_id = rp.role_id
INNER JOIN roles r ON r.id = ur.role_id
WHERE ur.user_id = ? AND r.organization_id = ?
ORDER BY p.name ASC`, ulidToBytes(userID), ulidToBytes(*orgID))
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func (s *Store) CountUsersWithPermissionInOrg(ctx context.Context, orgID theauth.ULID, perm string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT ur.user_id)
FROM user_roles ur
INNER JOIN role_permissions rp ON rp.role_id = ur.role_id
INNER JOIN permissions p ON p.id = rp.permission_id
INNER JOIN roles r ON r.id = ur.role_id
WHERE p.name = ? AND r.organization_id = ?`,
		perm, ulidToBytes(orgID),
	).Scan(&n)
	return n, err
}

func scanRole(row interface{ Scan(...interface{}) error }) (theauth.Role, error) {
	var (
		idB, orgIDB []byte
		name, desc  string
		created, up time.Time
	)
	if err := row.Scan(&idB, &orgIDB, &name, &desc, &created, &up); err != nil {
		return theauth.Role{}, err
	}
	return theauth.Role{
		ID:             bytesToULID(idB),
		OrganizationID: bytesToULIDPtr(orgIDB),
		Name:           name,
		Description:    desc,
		CreatedAt:      created.UTC(),
		UpdatedAt:      up.UTC(),
	}, nil
}
