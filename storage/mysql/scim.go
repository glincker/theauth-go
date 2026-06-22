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

// ---------- SCIM tokens ----------

func (s *Store) InsertSCIMToken(ctx context.Context, t theauth.SCIMToken) (theauth.SCIMToken, error) {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO scim_tokens (id, organization_id, token_hash, name, created_at)
VALUES (?, ?, ?, ?, ?)`,
		ulidToBytes(t.ID),
		ulidToBytes(t.OrganizationID),
		t.TokenHash,
		t.Name,
		timeUTC(t.CreatedAt),
	)
	if err != nil {
		return theauth.SCIMToken{}, err
	}
	got, err := s.SCIMTokenByHash(ctx, t.TokenHash)
	if err != nil {
		return theauth.SCIMToken{}, err
	}
	return *got, nil
}

func (s *Store) SCIMTokenByHash(ctx context.Context, hash []byte) (*theauth.SCIMToken, error) {
	t, err := scanSCIMToken(s.db.QueryRowContext(ctx, `
SELECT id, organization_id, token_hash, name, created_at, last_used_at, revoked_at
FROM scim_tokens WHERE token_hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) SCIMTokensByOrg(ctx context.Context, orgID theauth.ULID) ([]theauth.SCIMToken, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, organization_id, token_hash, name, created_at, last_used_at, revoked_at
FROM scim_tokens WHERE organization_id = ? ORDER BY created_at ASC`,
		ulidToBytes(orgID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []theauth.SCIMToken
	for rows.Next() {
		t, err := scanSCIMToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) RevokeSCIMTokenByID(ctx context.Context, id theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE scim_tokens SET revoked_at = ? WHERE id = ?`,
		timeUTC(at), ulidToBytes(id),
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

func (s *Store) TouchSCIMTokenLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE scim_tokens SET last_used_at = ? WHERE id = ?`,
		timeUTC(at), ulidToBytes(id),
	)
	return err
}

func scanSCIMToken(row interface{ Scan(...interface{}) error }) (theauth.SCIMToken, error) {
	var (
		idB, orgIDB []byte
		tokenHash   []byte
		name        string
		createdAt   time.Time
		lastUsedAt  sql.NullTime
		revokedAt   sql.NullTime
	)
	if err := row.Scan(&idB, &orgIDB, &tokenHash, &name, &createdAt, &lastUsedAt, &revokedAt); err != nil {
		return theauth.SCIMToken{}, err
	}
	return theauth.SCIMToken{
		ID:             bytesToULID(idB),
		OrganizationID: bytesToULID(orgIDB),
		TokenHash:      tokenHash,
		Name:           name,
		CreatedAt:      createdAt.UTC(),
		LastUsedAt:     nullTimeToPtr(lastUsedAt),
		RevokedAt:      nullTimeToPtr(revokedAt),
	}, nil
}

// ---------- Groups ----------

func (s *Store) InsertGroup(ctx context.Context, g theauth.Group) (theauth.Group, error) {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO `+"`groups`"+` (id, organization_id, display_name, external_id, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`,
		ulidToBytes(g.ID),
		ulidToBytes(g.OrganizationID),
		g.DisplayName,
		nullStringVal(g.ExternalID),
		timeUTC(g.CreatedAt),
		timeUTC(g.UpdatedAt),
	)
	if err != nil {
		if isMySQL1062(err) {
			return theauth.Group{}, storage.ErrNotFound
		}
		return theauth.Group{}, err
	}
	got, err := s.GroupByID(ctx, g.ID)
	if err != nil {
		return theauth.Group{}, err
	}
	return *got, nil
}

func (s *Store) GroupByID(ctx context.Context, id theauth.ULID) (*theauth.Group, error) {
	g, err := scanGroup(s.db.QueryRowContext(ctx, `
SELECT id, organization_id, display_name, external_id, created_at, updated_at
FROM `+"`groups`"+` WHERE id = ?`, ulidToBytes(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *Store) GroupByExternalIDInOrg(ctx context.Context, orgID theauth.ULID, externalID string) (*theauth.Group, error) {
	g, err := scanGroup(s.db.QueryRowContext(ctx, `
SELECT id, organization_id, display_name, external_id, created_at, updated_at
FROM `+"`groups`"+` WHERE organization_id = ? AND external_id = ?`,
		ulidToBytes(orgID), externalID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *Store) UpdateGroup(ctx context.Context, g theauth.Group) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE `+"`groups`"+` SET display_name = ?, external_id = ?, updated_at = ? WHERE id = ?`,
		g.DisplayName, nullStringVal(g.ExternalID), timeUTC(time.Now()), ulidToBytes(g.ID),
	)
	return err
}

func (s *Store) DeleteGroup(ctx context.Context, id theauth.ULID) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM `+"`groups`"+` WHERE id = ?`, ulidToBytes(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) ListGroupsByOrganization(ctx context.Context, orgID theauth.ULID, offset, limit int, filter theauth.SCIMGroupFilter) ([]theauth.Group, int, error) {
	if limit <= 0 {
		limit = 100
	}
	var wheres []string
	var args []interface{}
	wheres = append(wheres, "organization_id = ?")
	args = append(args, ulidToBytes(orgID))
	if filter.DisplayName != "" {
		wheres = append(wheres, "display_name = ?")
		args = append(args, filter.DisplayName)
	}
	where := strings.Join(wheres, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM `groups` WHERE "+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}
	listArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, organization_id, display_name, external_id, created_at, updated_at FROM `groups` WHERE "+where+" ORDER BY created_at ASC LIMIT ? OFFSET ?",
		listArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []theauth.Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, g)
	}
	return out, total, rows.Err()
}

func (s *Store) SetGroupMembers(ctx context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM group_members WHERE group_id = ?`, ulidToBytes(groupID),
	); err != nil {
		return err
	}
	for _, uid := range userIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`,
			ulidToBytes(groupID), ulidToBytes(uid),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AddGroupMembers(ctx context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	for _, uid := range userIDs {
		if _, err := s.db.ExecContext(ctx,
			`INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`,
			ulidToBytes(groupID), ulidToBytes(uid),
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) RemoveGroupMembers(ctx context.Context, groupID theauth.ULID, userIDs []theauth.ULID) error {
	for _, uid := range userIDs {
		if _, err := s.db.ExecContext(ctx,
			`DELETE FROM group_members WHERE group_id = ? AND user_id = ?`,
			ulidToBytes(groupID), ulidToBytes(uid),
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GroupMembers(ctx context.Context, groupID theauth.ULID) ([]theauth.ULID, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT user_id FROM group_members WHERE group_id = ? ORDER BY user_id ASC`,
		ulidToBytes(groupID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []theauth.ULID
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, bytesToULID(b))
	}
	return out, rows.Err()
}

func scanGroup(row interface{ Scan(...interface{}) error }) (theauth.Group, error) {
	var (
		idB, orgIDB    []byte
		displayName    string
		externalID     sql.NullString
		createdAt, upd time.Time
	)
	if err := row.Scan(&idB, &orgIDB, &displayName, &externalID, &createdAt, &upd); err != nil {
		return theauth.Group{}, err
	}
	extID := ""
	if externalID.Valid {
		extID = externalID.String
	}
	return theauth.Group{
		ID:             bytesToULID(idB),
		OrganizationID: bytesToULID(orgIDB),
		DisplayName:    displayName,
		ExternalID:     extID,
		CreatedAt:      createdAt.UTC(),
		UpdatedAt:      upd.UTC(),
	}, nil
}
