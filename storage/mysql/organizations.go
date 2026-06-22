package mysql

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

// ---------- Organizations ----------

func (s *Store) InsertOrganization(ctx context.Context, o theauth.Organization) (theauth.Organization, error) {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO organizations (id, name, slug, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)`,
		ulidToBytes(o.ID),
		o.Name,
		strings.ToLower(o.Slug),
		timeUTC(o.CreatedAt),
		timeUTC(o.UpdatedAt),
	)
	if err != nil {
		if isMySQL1062(err) {
			return theauth.Organization{}, theauth.ErrSlugTaken
		}
		return theauth.Organization{}, err
	}
	got, err := s.OrganizationByID(ctx, o.ID)
	if err != nil {
		return theauth.Organization{}, err
	}
	return *got, nil
}

func (s *Store) OrganizationByID(ctx context.Context, id theauth.ULID) (*theauth.Organization, error) {
	o, err := scanOrg(s.db.QueryRowContext(ctx,
		`SELECT id, name, slug, created_at, updated_at FROM organizations WHERE id = ?`,
		ulidToBytes(id),
	))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func (s *Store) OrganizationBySlug(ctx context.Context, slug string) (*theauth.Organization, error) {
	o, err := scanOrg(s.db.QueryRowContext(ctx,
		`SELECT id, name, slug, created_at, updated_at FROM organizations WHERE slug = ?`,
		strings.ToLower(slug),
	))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func (s *Store) UpdateOrganization(ctx context.Context, o theauth.Organization) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE organizations SET name = ?, slug = ?, updated_at = ? WHERE id = ?`,
		o.Name, strings.ToLower(o.Slug), timeUTC(time.Now()), ulidToBytes(o.ID),
	)
	if err != nil {
		if isMySQL1062(err) {
			return theauth.ErrSlugTaken
		}
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteOrganization(ctx context.Context, id theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM organizations WHERE id = ?`,
		ulidToBytes(id),
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

func scanOrg(row interface{ Scan(...interface{}) error }) (theauth.Organization, error) {
	var (
		idB              []byte
		name, slug       string
		createdAt, updAt time.Time
	)
	if err := row.Scan(&idB, &name, &slug, &createdAt, &updAt); err != nil {
		return theauth.Organization{}, err
	}
	return theauth.Organization{
		ID:        bytesToULID(idB),
		Name:      name,
		Slug:      slug,
		CreatedAt: createdAt.UTC(),
		UpdatedAt: updAt.UTC(),
	}, nil
}

// ---------- Organization members ----------

func (s *Store) UpsertOrganizationMember(ctx context.Context, m theauth.OrganizationMember) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO organization_members (organization_id, user_id, role, joined_at)
VALUES (?, ?, ?, ?)
ON DUPLICATE KEY UPDATE role = VALUES(role)`,
		ulidToBytes(m.OrganizationID),
		ulidToBytes(m.UserID),
		m.Role,
		timeUTC(m.JoinedAt),
	)
	return err
}

func (s *Store) DeleteOrganizationMember(ctx context.Context, orgID, userID theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM organization_members WHERE organization_id = ? AND user_id = ?`,
		ulidToBytes(orgID), ulidToBytes(userID),
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

func (s *Store) OrganizationMembersByOrg(ctx context.Context, orgID theauth.ULID) ([]theauth.OrganizationMember, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT organization_id, user_id, role, joined_at
FROM organization_members WHERE organization_id = ? ORDER BY joined_at ASC`,
		ulidToBytes(orgID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanOrgMembers(rows)
}

func (s *Store) OrganizationsByUser(ctx context.Context, userID theauth.ULID) ([]theauth.Organization, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT o.id, o.name, o.slug, o.created_at, o.updated_at
FROM organizations o
INNER JOIN organization_members om ON om.organization_id = o.id
WHERE om.user_id = ? ORDER BY o.created_at ASC`,
		ulidToBytes(userID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []theauth.Organization
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) OrganizationMemberRole(ctx context.Context, orgID, userID theauth.ULID) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx,
		`SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?`,
		ulidToBytes(orgID), ulidToBytes(userID),
	).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", storage.ErrNotFound
	}
	return role, err
}

func scanOrgMembers(rows *sql.Rows) ([]theauth.OrganizationMember, error) {
	var out []theauth.OrganizationMember
	for rows.Next() {
		var (
			orgIDB, userIDB []byte
			role            string
			joinedAt        time.Time
		)
		if err := rows.Scan(&orgIDB, &userIDB, &role, &joinedAt); err != nil {
			return nil, err
		}
		out = append(out, theauth.OrganizationMember{
			OrganizationID: bytesToULID(orgIDB),
			UserID:         bytesToULID(userIDB),
			Role:           role,
			JoinedAt:       joinedAt.UTC(),
		})
	}
	return out, rows.Err()
}
