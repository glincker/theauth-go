package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
	sqlcgen "github.com/glincker/theauth-go/v2/storage/postgres/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/oklog/ulid/v2"
)

// v1.0 storage extension: permissions, roles, role_permissions, user_roles,
// audit_events. All methods are additive; v0.7 callers never invoke them.

// helpers

func ulidPtrToPgUUID(p *theauth.ULID) pgtype.UUID {
	if p == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: [16]byte(*p), Valid: true}
}

func pgUUIDToULIDPtr(u pgtype.UUID) *theauth.ULID {
	if !u.Valid {
		return nil
	}
	id := theauth.ULID(u.Bytes)
	return &id
}

func nullableText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// permissions

func rowToPermission(r sqlcgen.Permission) theauth.Permission {
	return theauth.Permission{
		ID:          pgUUIDToULID(r.ID),
		Name:        r.Name,
		Description: r.Description,
		CreatedAt:   tsToTime(r.CreatedAt),
	}
}

func (s *Store) InsertPermission(ctx context.Context, p theauth.Permission) (theauth.Permission, error) {
	created := p.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	row, err := s.q.InsertPermission(ctx, sqlcgen.InsertPermissionParams{
		ID:          ulidToPgUUID(p.ID),
		Name:        p.Name,
		Description: p.Description,
		CreatedAt:   timeToTs(created),
	})
	if err != nil {
		return theauth.Permission{}, err
	}
	return rowToPermission(row), nil
}

func (s *Store) PermissionByName(ctx context.Context, name string) (*theauth.Permission, error) {
	row, err := s.q.PermissionByName(ctx, name)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	p := rowToPermission(row)
	return &p, nil
}

func (s *Store) ListPermissions(ctx context.Context) ([]theauth.Permission, error) {
	rows, err := s.q.ListPermissions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]theauth.Permission, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToPermission(r))
	}
	return out, nil
}

// roles

func rowToRole(r sqlcgen.Role) theauth.Role {
	return theauth.Role{
		ID:             pgUUIDToULID(r.ID),
		OrganizationID: pgUUIDToULIDPtr(r.OrganizationID),
		Name:           r.Name,
		Description:    r.Description,
		CreatedAt:      tsToTime(r.CreatedAt),
		UpdatedAt:      tsToTime(r.UpdatedAt),
	}
}

func (s *Store) InsertRole(ctx context.Context, r theauth.Role) (theauth.Role, error) {
	created := r.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	updated := r.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	row, err := s.q.InsertRole(ctx, sqlcgen.InsertRoleParams{
		ID:             ulidToPgUUID(r.ID),
		OrganizationID: ulidPtrToPgUUID(r.OrganizationID),
		Name:           r.Name,
		Description:    r.Description,
		CreatedAt:      timeToTs(created),
		UpdatedAt:      timeToTs(updated),
	})
	if err != nil {
		return theauth.Role{}, err
	}
	return rowToRole(row), nil
}

func (s *Store) UpdateRoleRow(ctx context.Context, r theauth.Role) (theauth.Role, error) {
	row, err := s.q.UpdateRoleRow(ctx, sqlcgen.UpdateRoleRowParams{
		ID:          ulidToPgUUID(r.ID),
		Name:        r.Name,
		Description: r.Description,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return theauth.Role{}, storage.ErrNotFound
		}
		return theauth.Role{}, err
	}
	return rowToRole(row), nil
}

func (s *Store) DeleteRole(ctx context.Context, id theauth.ULID) error {
	affected, err := s.q.DeleteRoleRow(ctx, ulidToPgUUID(id))
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) RoleByID(ctx context.Context, id theauth.ULID) (*theauth.Role, error) {
	row, err := s.q.RoleByID(ctx, ulidToPgUUID(id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	r := rowToRole(row)
	perms, err := s.q.PermissionsByRoleID(ctx, ulidToPgUUID(id))
	if err != nil {
		return nil, err
	}
	r.Permissions = perms
	return &r, nil
}

func (s *Store) RoleByOrgAndName(ctx context.Context, orgID *theauth.ULID, name string) (*theauth.Role, error) {
	row, err := s.q.RoleByOrgAndName(ctx, sqlcgen.RoleByOrgAndNameParams{
		Name:           name,
		OrganizationID: ulidPtrToPgUUID(orgID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	r := rowToRole(row)
	perms, err := s.q.PermissionsByRoleID(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	r.Permissions = perms
	return &r, nil
}

func (s *Store) RolesByOrganization(ctx context.Context, orgID *theauth.ULID) ([]theauth.Role, error) {
	rows, err := s.q.RolesByOrganization(ctx, ulidPtrToPgUUID(orgID))
	if err != nil {
		return nil, err
	}
	out := make([]theauth.Role, 0, len(rows))
	for _, r := range rows {
		role := rowToRole(r)
		perms, err := s.q.PermissionsByRoleID(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		role.Permissions = perms
		out = append(out, role)
	}
	return out, nil
}

func (s *Store) SetRolePermissions(ctx context.Context, roleID theauth.ULID, permissionIDs []theauth.ULID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.q.WithTx(tx)
	if err := qtx.DeleteRolePermissions(ctx, ulidToPgUUID(roleID)); err != nil {
		return err
	}
	for _, pid := range permissionIDs {
		if err := qtx.InsertRolePermission(ctx, sqlcgen.InsertRolePermissionParams{
			RoleID:       ulidToPgUUID(roleID),
			PermissionID: ulidToPgUUID(pid),
		}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) PermissionsByRole(ctx context.Context, roleID theauth.ULID) ([]string, error) {
	return s.q.PermissionsByRoleID(ctx, ulidToPgUUID(roleID))
}

// user_roles

func (s *Store) GrantUserRole(ctx context.Context, ur theauth.UserRole) error {
	granted := ur.GrantedAt
	if granted.IsZero() {
		granted = time.Now()
	}
	return s.q.GrantUserRole(ctx, sqlcgen.GrantUserRoleParams{
		UserID:    ulidToPgUUID(ur.UserID),
		RoleID:    ulidToPgUUID(ur.RoleID),
		GrantedAt: timeToTs(granted),
		GrantedBy: ulidPtrToPgUUID(ur.GrantedBy),
	})
}

func (s *Store) RevokeUserRole(ctx context.Context, userID, roleID theauth.ULID) error {
	affected, err := s.q.RevokeUserRole(ctx, sqlcgen.RevokeUserRoleParams{
		UserID: ulidToPgUUID(userID),
		RoleID: ulidToPgUUID(roleID),
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) RolesForUser(ctx context.Context, userID theauth.ULID, orgID *theauth.ULID) ([]theauth.Role, error) {
	rows, err := s.q.RolesForUser(ctx, sqlcgen.RolesForUserParams{
		UserID:         ulidToPgUUID(userID),
		OrganizationID: ulidPtrToPgUUID(orgID),
	})
	if err != nil {
		return nil, err
	}
	out := make([]theauth.Role, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToRole(r))
	}
	return out, nil
}

func (s *Store) PermissionsForUser(ctx context.Context, userID theauth.ULID, orgID *theauth.ULID) ([]string, error) {
	return s.q.PermissionsForUserInOrg(ctx, sqlcgen.PermissionsForUserInOrgParams{
		UserID:         ulidToPgUUID(userID),
		OrganizationID: ulidPtrToPgUUID(orgID),
	})
}

func (s *Store) CountUsersWithPermissionInOrg(ctx context.Context, orgID theauth.ULID, perm string) (int, error) {
	n, err := s.q.CountUsersWithPermissionInOrg(ctx, sqlcgen.CountUsersWithPermissionInOrgParams{
		Name:           perm,
		OrganizationID: ulidToPgUUID(orgID),
	})
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

func pgTextString(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

func encodeKeysetCursor(ts time.Time, id theauth.ULID) string {
	raw := strconv.FormatInt(ts.UnixMicro(), 10) + ":" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeKeysetCursor(s string) (time.Time, theauth.ULID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, theauth.ULID{}, fmt.Errorf("cursor decode: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return time.Time{}, theauth.ULID{}, errors.New("cursor format")
	}
	micros, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, theauth.ULID{}, fmt.Errorf("cursor micros: %w", err)
	}
	id, err := ulid.Parse(parts[1])
	if err != nil {
		return time.Time{}, theauth.ULID{}, fmt.Errorf("cursor ulid: %w", err)
	}
	return time.UnixMicro(micros), id, nil
}
