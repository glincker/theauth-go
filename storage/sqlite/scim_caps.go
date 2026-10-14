package sqlite

import (
	"context"
	"database/sql"
	"math"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// scim_caps.go: SCIMStorage over migration 0015. Tokens are stored as the
// caller's sha256 hash only; the adapter never sees the plaintext.

var _ theauth.SCIMStorage = (*Store)(nil)

const scimTokenCols = `id, organization_id, token_hash, name, created_at, last_used_at, revoked_at`

func scanSCIMToken(r scanner) (theauth.SCIMToken, error) {
	var (
		id, org, name       string
		hash                []byte
		created             int64
		lastUsed, revokedAt sql.NullInt64
	)
	if err := r.Scan(&id, &org, &hash, &name, &created, &lastUsed, &revokedAt); err != nil {
		return theauth.SCIMToken{}, err
	}
	tid, err := parseID(id)
	if err != nil {
		return theauth.SCIMToken{}, err
	}
	oid, err := parseID(org)
	if err != nil {
		return theauth.SCIMToken{}, err
	}
	return theauth.SCIMToken{
		ID: tid, OrganizationID: oid, TokenHash: hash, Name: name, CreatedAt: fromMicro(created),
		LastUsedAt: fromNullMicro(lastUsed), RevokedAt: fromNullMicro(revokedAt),
	}, nil
}

// InsertSCIMToken stores a token hash bound to an existing organization.
func (s *Store) InsertSCIMToken(ctx context.Context, t theauth.SCIMToken) (theauth.SCIMToken, error) {
	out, err := scanSCIMToken(s.db.QueryRowContext(ctx, s.q(`
INSERT INTO theauth_scim_tokens (id, organization_id, token_hash, name, created_at) VALUES (?, ?, ?, ?, ?)
RETURNING `+scimTokenCols), idStr(t.ID), idStr(t.OrganizationID), t.TokenHash, t.Name, toMicro(orNow(t.CreatedAt))))
	if err != nil {
		return theauth.SCIMToken{}, wrap("insert scim token", err)
	}
	return out, nil
}

// SCIMTokenByHash returns the token row for a hash, including revoked ones.
func (s *Store) SCIMTokenByHash(ctx context.Context, hash []byte) (*theauth.SCIMToken, error) {
	t, err := scanSCIMToken(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+scimTokenCols+` FROM theauth_scim_tokens WHERE token_hash = ?`), hash))
	if err != nil {
		return nil, notFoundOr("scim token by hash", err)
	}
	return &t, nil
}

// SCIMTokensByOrg lists an organization's tokens, oldest first.
func (s *Store) SCIMTokensByOrg(ctx context.Context, orgID theauth.ULID) ([]theauth.SCIMToken, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+scimTokenCols+
		` FROM theauth_scim_tokens WHERE organization_id = ? ORDER BY created_at ASC, id ASC`), idStr(orgID))
	if err != nil {
		return nil, wrap("scim tokens by org", err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.SCIMToken{}
	for rows.Next() {
		t, err := scanSCIMToken(rows)
		if err != nil {
			return nil, wrap("scim tokens by org", err)
		}
		out = append(out, t)
	}
	return out, wrap("scim tokens by org", rows.Err())
}

// RevokeSCIMTokenByID marks a token revoked.
func (s *Store) RevokeSCIMTokenByID(ctx context.Context, id theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE theauth_scim_tokens SET revoked_at = ? WHERE id = ?`),
		toMicro(at), idStr(id))
	if err != nil {
		return wrap("revoke scim token", err)
	}
	return requireRows("revoke scim token", res)
}

// TouchSCIMTokenLastUsed records the last successful use of a token.
func (s *Store) TouchSCIMTokenLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE theauth_scim_tokens SET last_used_at = ? WHERE id = ?`),
		toMicro(at), idStr(id))
	return wrap("touch scim token", err)
}

const scopedUserCols = `u.id, u.email, u.email_verified_at, u.name, u.avatar_url, u.created_at, u.updated_at,
u.external_id, u.given_name, u.family_name, u.display_name`

func clampWindow(offset, limit int) (int, int) {
	if limit <= 0 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	if limit > math.MaxInt32 {
		limit = math.MaxInt32
	}
	if offset > math.MaxInt32 {
		offset = math.MaxInt32
	}
	return offset, limit
}

// ListUsersByOrganization pages through an organization's members matching the equality filter.
func (s *Store) ListUsersByOrganization(ctx context.Context, orgID theauth.ULID, offset, limit int, filter theauth.SCIMUserFilter) ([]theauth.User, int, error) {
	offset, limit = clampWindow(offset, limit)
	const where = `FROM theauth_users u JOIN theauth_organization_members m ON m.user_id = u.id
WHERE m.organization_id = ?
  AND (? = '' OR u.email = ?)
  AND (? = '' OR u.external_id = ?)
  AND (? = '' OR u.email = ?)`
	args := []any{idStr(orgID), filter.UserName, filter.UserName, filter.ExternalID, filter.ExternalID, filter.Email, filter.Email}
	var total int
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT count(*) `+where), args...).Scan(&total); err != nil {
		return nil, 0, wrap("count users by organization", err)
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+scopedUserCols+` `+where+
		` ORDER BY u.created_at ASC, u.id ASC LIMIT ? OFFSET ?`), append(args, limit, offset)...)
	if err != nil {
		return nil, 0, wrap("list users by organization", err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, wrap("list users by organization", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, wrap("list users by organization", err)
	}
	return out, total, nil
}

// UserByExternalIDInOrg returns the organization member carrying the SCIM external ID.
func (s *Store) UserByExternalIDInOrg(ctx context.Context, orgID theauth.ULID, externalID string) (*theauth.User, error) {
	if externalID == "" {
		return nil, theauth.ErrStorageNotFound
	}
	u, err := scanUser(s.db.QueryRowContext(ctx, s.q(`SELECT `+scopedUserCols+`
FROM theauth_users u JOIN theauth_organization_members m ON m.user_id = u.id
WHERE m.organization_id = ? AND u.external_id = ?
ORDER BY u.created_at ASC, u.id ASC LIMIT 1`), idStr(orgID), externalID))
	if err != nil {
		return nil, notFoundOr("user by external id in org", err)
	}
	return &u, nil
}

// UpdateUserSCIM rewrites the SCIM-managed profile fields of a user.
func (s *Store) UpdateUserSCIM(ctx context.Context, u theauth.User) error {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_users SET email = ?, name = ?, avatar_url = ?, external_id = ?, given_name = ?,
    family_name = ?, display_name = ?, updated_at = ?
WHERE id = ?`),
		u.Email, u.Name, u.AvatarURL, u.ExternalID, u.GivenName, u.FamilyName, u.DisplayName,
		toMicro(time.Now()), idStr(u.ID))
	if err != nil {
		return wrap("update user scim", err)
	}
	return requireRows("update user scim", res)
}

const groupCols = `id, organization_id, display_name, external_id, created_at, updated_at`

func scanGroup(r scanner) (theauth.Group, error) {
	var (
		id, org, name    string
		ext              sql.NullString
		created, updated int64
	)
	if err := r.Scan(&id, &org, &name, &ext, &created, &updated); err != nil {
		return theauth.Group{}, err
	}
	gid, err := parseID(id)
	if err != nil {
		return theauth.Group{}, err
	}
	oid, err := parseID(org)
	if err != nil {
		return theauth.Group{}, err
	}
	return theauth.Group{
		ID: gid, OrganizationID: oid, DisplayName: name, ExternalID: ext.String,
		CreatedAt: fromMicro(created), UpdatedAt: fromMicro(updated),
	}, nil
}

func nullableExternalID(v string) sql.NullString {
	return sql.NullString{String: v, Valid: v != ""}
}

// ListGroupsByOrganization pages through an organization's groups matching the equality filter.
func (s *Store) ListGroupsByOrganization(ctx context.Context, orgID theauth.ULID, offset, limit int, filter theauth.SCIMGroupFilter) ([]theauth.Group, int, error) {
	offset, limit = clampWindow(offset, limit)
	const where = `FROM theauth_groups
WHERE organization_id = ? AND (? = '' OR display_name = ?) AND (? = '' OR external_id = ?)`
	args := []any{idStr(orgID), filter.DisplayName, filter.DisplayName, filter.ExternalID, filter.ExternalID}
	var total int
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT count(*) `+where), args...).Scan(&total); err != nil {
		return nil, 0, wrap("count groups by organization", err)
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+groupCols+` `+where+
		` ORDER BY created_at ASC, id ASC LIMIT ? OFFSET ?`), append(args, limit, offset)...)
	if err != nil {
		return nil, 0, wrap("list groups by organization", err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, 0, wrap("list groups by organization", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, wrap("list groups by organization", err)
	}
	return out, total, nil
}

// InsertGroup stores a group; (organization, display name) and (organization, external ID) are unique.
func (s *Store) InsertGroup(ctx context.Context, g theauth.Group) (theauth.Group, error) {
	created := orNow(g.CreatedAt)
	updated := g.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	out, err := scanGroup(s.db.QueryRowContext(ctx, s.q(`
INSERT INTO theauth_groups (`+groupCols+`) VALUES (?, ?, ?, ?, ?, ?) RETURNING `+groupCols),
		idStr(g.ID), idStr(g.OrganizationID), g.DisplayName, nullableExternalID(g.ExternalID),
		toMicro(created), toMicro(updated)))
	if err != nil {
		return theauth.Group{}, wrap("insert group", err)
	}
	return out, nil
}

// GroupByID returns the group with the given ID.
func (s *Store) GroupByID(ctx context.Context, id theauth.ULID) (*theauth.Group, error) {
	g, err := scanGroup(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+groupCols+` FROM theauth_groups WHERE id = ?`), idStr(id)))
	if err != nil {
		return nil, notFoundOr("group by id", err)
	}
	return &g, nil
}

// GroupByExternalIDInOrg returns the group carrying the external ID in one organization.
func (s *Store) GroupByExternalIDInOrg(ctx context.Context, orgID theauth.ULID, externalID string) (*theauth.Group, error) {
	if externalID == "" {
		return nil, theauth.ErrStorageNotFound
	}
	g, err := scanGroup(s.db.QueryRowContext(ctx, s.q(`SELECT `+groupCols+
		` FROM theauth_groups WHERE organization_id = ? AND external_id = ?`), idStr(orgID), externalID))
	if err != nil {
		return nil, notFoundOr("group by external id", err)
	}
	return &g, nil
}

// UpdateGroup rewrites a group's display name and external ID.
func (s *Store) UpdateGroup(ctx context.Context, g theauth.Group) error {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_groups SET display_name = ?, external_id = ?, updated_at = ? WHERE id = ?`),
		g.DisplayName, nullableExternalID(g.ExternalID), toMicro(time.Now()), idStr(g.ID))
	if err != nil {
		return wrap("update group", err)
	}
	return requireRows("update group", res)
}

// DeleteGroup removes a group and, by cascade, its memberships.
func (s *Store) DeleteGroup(ctx context.Context, id theauth.ULID) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM theauth_groups WHERE id = ?`), idStr(id))
	if err != nil {
		return wrap("delete group", err)
	}
	return requireRows("delete group", res)
}

// SetGroupMembers replaces the member set atomically.
func (s *Store) SetGroupMembers(ctx context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	return s.inTx(ctx, "set group members", func(tx DBTX) error {
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM theauth_group_members WHERE group_id = ?`), idStr(groupID)); err != nil {
			return err
		}
		return s.insertGroupMembers(ctx, tx, groupID, userIDs)
	})
}

// AddGroupMembers adds members, ignoring those already present.
func (s *Store) AddGroupMembers(ctx context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	return s.inTx(ctx, "add group members", func(tx DBTX) error {
		return s.insertGroupMembers(ctx, tx, groupID, userIDs)
	})
}

func (s *Store) insertGroupMembers(ctx context.Context, tx DBTX, groupID theauth.ULID, userIDs []theauth.ULID) error {
	for _, u := range userIDs {
		if _, err := tx.ExecContext(ctx, s.q(
			`INSERT INTO theauth_group_members (group_id, user_id) VALUES (?, ?) ON CONFLICT DO NOTHING`),
			idStr(groupID), idStr(u)); err != nil {
			return err
		}
	}
	return nil
}

// RemoveGroupMembers removes members; absent users are ignored.
func (s *Store) RemoveGroupMembers(ctx context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	return s.inTx(ctx, "remove group members", func(tx DBTX) error {
		for _, u := range userIDs {
			if _, err := tx.ExecContext(ctx, s.q(
				`DELETE FROM theauth_group_members WHERE group_id = ? AND user_id = ?`),
				idStr(groupID), idStr(u)); err != nil {
				return err
			}
		}
		return nil
	})
}

// GroupMembers lists a group's member user IDs.
func (s *Store) GroupMembers(ctx context.Context, groupID theauth.ULID) ([]theauth.ULID, error) {
	rows, err := s.db.QueryContext(ctx, s.q(
		`SELECT user_id FROM theauth_group_members WHERE group_id = ? ORDER BY user_id ASC`), idStr(groupID))
	if err != nil {
		return nil, wrap("group members", err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.ULID{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, wrap("group members", err)
		}
		id, err := parseID(raw)
		if err != nil {
			return nil, wrap("group members", err)
		}
		out = append(out, id)
	}
	return out, wrap("group members", rows.Err())
}
