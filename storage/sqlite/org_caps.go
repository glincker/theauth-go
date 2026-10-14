package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// org_caps.go: OrganizationStorage over migration 0013.

var _ theauth.OrganizationStorage = (*Store)(nil)

const orgCols = `id, name, slug, created_at, updated_at`

func scanOrganization(r scanner) (theauth.Organization, error) {
	var (
		id, name, slug   string
		created, updated int64
	)
	if err := r.Scan(&id, &name, &slug, &created, &updated); err != nil {
		return theauth.Organization{}, err
	}
	oid, err := parseID(id)
	if err != nil {
		return theauth.Organization{}, err
	}
	return theauth.Organization{ID: oid, Name: name, Slug: slug, CreatedAt: fromMicro(created), UpdatedAt: fromMicro(updated)}, nil
}

func isUniqueOn(err error, column string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") && strings.Contains(msg, column)
}

// InsertOrganization stores o with a lowercased slug and returns ErrSlugTaken on a duplicate.
func (s *Store) InsertOrganization(ctx context.Context, o theauth.Organization) (theauth.Organization, error) {
	created := orNow(o.CreatedAt)
	updated := o.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	out, err := scanOrganization(s.db.QueryRowContext(ctx, s.q(`
INSERT INTO theauth_organizations (id, name, slug, created_at, updated_at) VALUES (?, ?, ?, ?, ?)
RETURNING `+orgCols), idStr(o.ID), o.Name, strings.ToLower(o.Slug), toMicro(created), toMicro(updated)))
	if err != nil {
		if isUniqueOn(err, "slug") {
			return theauth.Organization{}, theauth.ErrSlugTaken
		}
		return theauth.Organization{}, wrap("insert organization", err)
	}
	return out, nil
}

// OrganizationByID returns the organization with the given ID.
func (s *Store) OrganizationByID(ctx context.Context, id theauth.ULID) (*theauth.Organization, error) {
	o, err := scanOrganization(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+orgCols+` FROM theauth_organizations WHERE id = ?`), idStr(id)))
	if err != nil {
		return nil, notFoundOr("organization by id", err)
	}
	return &o, nil
}

// OrganizationBySlug returns the organization with the given slug, compared case-insensitively.
func (s *Store) OrganizationBySlug(ctx context.Context, slug string) (*theauth.Organization, error) {
	o, err := scanOrganization(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+orgCols+` FROM theauth_organizations WHERE slug = ?`), strings.ToLower(slug)))
	if err != nil {
		return nil, notFoundOr("organization by slug", err)
	}
	return &o, nil
}

// UpdateOrganization rewrites the name and slug and returns ErrSlugTaken on a duplicate slug.
func (s *Store) UpdateOrganization(ctx context.Context, o theauth.Organization) error {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_organizations SET name = ?, slug = ?, updated_at = ? WHERE id = ?`),
		o.Name, strings.ToLower(o.Slug), toMicro(time.Now()), idStr(o.ID))
	if err != nil {
		if isUniqueOn(err, "slug") {
			return theauth.ErrSlugTaken
		}
		return wrap("update organization", err)
	}
	return requireRows("update organization", res)
}

// DeleteOrganization removes the organization and, by cascade, its members, connections, tokens, groups and roles.
func (s *Store) DeleteOrganization(ctx context.Context, id theauth.ULID) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM theauth_organizations WHERE id = ?`), idStr(id))
	if err != nil {
		return wrap("delete organization", err)
	}
	return requireRows("delete organization", res)
}

// UpsertOrganizationMember adds a member or updates the role of an existing one.
func (s *Store) UpsertOrganizationMember(ctx context.Context, m theauth.OrganizationMember) error {
	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_organization_members (organization_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)
ON CONFLICT (organization_id, user_id) DO UPDATE SET role = excluded.role`),
		idStr(m.OrganizationID), idStr(m.UserID), m.Role, toMicro(orNow(m.JoinedAt)))
	return wrap("upsert organization member", err)
}

// DeleteOrganizationMember removes one membership.
func (s *Store) DeleteOrganizationMember(ctx context.Context, orgID, userID theauth.ULID) error {
	res, err := s.db.ExecContext(ctx, s.q(
		`DELETE FROM theauth_organization_members WHERE organization_id = ? AND user_id = ?`),
		idStr(orgID), idStr(userID))
	if err != nil {
		return wrap("delete organization member", err)
	}
	return requireRows("delete organization member", res)
}

// OrganizationMembersByOrg lists an organization's members, oldest first.
func (s *Store) OrganizationMembersByOrg(ctx context.Context, orgID theauth.ULID) ([]theauth.OrganizationMember, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`
SELECT organization_id, user_id, role, joined_at FROM theauth_organization_members
WHERE organization_id = ? ORDER BY joined_at ASC, user_id ASC`), idStr(orgID))
	if err != nil {
		return nil, wrap("organization members", err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.OrganizationMember{}
	for rows.Next() {
		var org, user, role string
		var joined int64
		if err := rows.Scan(&org, &user, &role, &joined); err != nil {
			return nil, wrap("organization members", err)
		}
		oid, err := parseID(org)
		if err != nil {
			return nil, wrap("organization members", err)
		}
		uid, err := parseID(user)
		if err != nil {
			return nil, wrap("organization members", err)
		}
		out = append(out, theauth.OrganizationMember{OrganizationID: oid, UserID: uid, Role: role, JoinedAt: fromMicro(joined)})
	}
	return out, wrap("organization members", rows.Err())
}

// OrganizationsByUser lists the organizations a user belongs to, oldest first.
func (s *Store) OrganizationsByUser(ctx context.Context, userID theauth.ULID) ([]theauth.Organization, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`
SELECT o.id, o.name, o.slug, o.created_at, o.updated_at FROM theauth_organizations o
JOIN theauth_organization_members m ON m.organization_id = o.id
WHERE m.user_id = ? ORDER BY o.created_at ASC, o.id ASC`), idStr(userID))
	if err != nil {
		return nil, wrap("organizations by user", err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.Organization{}
	for rows.Next() {
		o, err := scanOrganization(rows)
		if err != nil {
			return nil, wrap("organizations by user", err)
		}
		out = append(out, o)
	}
	return out, wrap("organizations by user", rows.Err())
}

// OrganizationMemberRole returns the member's role, or ErrStorageNotFound when the user is not a member.
func (s *Store) OrganizationMemberRole(ctx context.Context, orgID, userID theauth.ULID) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx, s.q(
		`SELECT role FROM theauth_organization_members WHERE organization_id = ? AND user_id = ?`),
		idStr(orgID), idStr(userID)).Scan(&role)
	if err != nil {
		return "", notFoundOr("organization member role", err)
	}
	return role, nil
}

// SetSessionActiveOrganization points a session at an organization, or clears it when orgID is nil.
func (s *Store) SetSessionActiveOrganization(ctx context.Context, sessionID theauth.ULID, orgID *theauth.ULID) error {
	return s.inTx(ctx, "set session active organization", func(tx DBTX) error {
		var one int
		err := tx.QueryRowContext(ctx, s.q(`SELECT 1 FROM theauth_sessions WHERE id = ?`), idStr(sessionID)).Scan(&one)
		if err == sql.ErrNoRows {
			return theauth.ErrStorageNotFound
		}
		if err != nil {
			return err
		}
		if orgID == nil {
			_, err = tx.ExecContext(ctx, s.q(`DELETE FROM theauth_session_organizations WHERE session_id = ?`), idStr(sessionID))
			return err
		}
		_, err = tx.ExecContext(ctx, s.q(`
INSERT INTO theauth_session_organizations (session_id, organization_id) VALUES (?, ?)
ON CONFLICT (session_id) DO UPDATE SET organization_id = excluded.organization_id`),
			idStr(sessionID), idStr(*orgID))
		return err
	})
}

// attachActiveOrg fills ActiveOrganizationID. A schema without migration 0013 reads as no active organization.
func (s *Store) attachActiveOrg(ctx context.Context, sess *theauth.Session) error {
	var org string
	err := s.db.QueryRowContext(ctx, s.q(
		`SELECT organization_id FROM theauth_session_organizations WHERE session_id = ?`), idStr(sess.ID)).Scan(&org)
	switch {
	case err == nil:
		id, perr := parseID(org)
		if perr != nil {
			return perr
		}
		sess.ActiveOrganizationID = &id
		return nil
	case err == sql.ErrNoRows, isMissingTable(err):
		return nil
	default:
		return err
	}
}

func isMissingTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}
