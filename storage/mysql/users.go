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

// ---------- row scanner ----------

func scanUser(row interface {
	Scan(dest ...interface{}) error
}) (theauth.User, error) {
	var (
		idB             []byte
		email           string
		emailVerifiedAt sql.NullTime
		name, avatarURL string
		createdAt       time.Time
		updatedAt       time.Time
		externalID      sql.NullString
		givenName       sql.NullString
		familyName      sql.NullString
		displayName     sql.NullString
	)
	err := row.Scan(
		&idB, &email, &emailVerifiedAt,
		&name, &avatarURL,
		&createdAt, &updatedAt,
		&externalID, &givenName, &familyName, &displayName,
	)
	if err != nil {
		return theauth.User{}, err
	}
	return theauth.User{
		ID:              bytesToULID(idB),
		Email:           email,
		EmailVerifiedAt: nullTimeToPtr(emailVerifiedAt),
		Name:            name,
		AvatarURL:       avatarURL,
		CreatedAt:       createdAt.UTC(),
		UpdatedAt:       updatedAt.UTC(),
		ExternalID:      nullStringScan(externalID),
		GivenName:       nullStringScan(givenName),
		FamilyName:      nullStringScan(familyName),
		DisplayName:     nullStringScan(displayName),
	}, nil
}

const selectUserColumns = `
SELECT id, email, email_verified_at, name, avatar_url, created_at, updated_at,
       external_id, given_name, family_name, display_name
FROM users`

// ---------- Users ----------

func (s *Store) CreateUser(ctx context.Context, u theauth.User) (theauth.User, error) {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO users (id, email, email_verified_at, name, avatar_url, created_at, updated_at,
                   external_id, given_name, family_name, display_name)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(u.ID),
		strings.ToLower(u.Email),
		timePtrToNull(u.EmailVerifiedAt),
		u.Name,
		u.AvatarURL,
		timeUTC(u.CreatedAt),
		timeUTC(u.UpdatedAt),
		u.ExternalID,
		u.GivenName,
		u.FamilyName,
		u.DisplayName,
	)
	if err != nil {
		return theauth.User{}, err
	}
	got, err := s.UserByID(ctx, u.ID)
	if err != nil {
		return theauth.User{}, err
	}
	return *got, nil
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*theauth.User, error) {
	row := s.db.QueryRowContext(ctx,
		selectUserColumns+` WHERE email = ?`,
		strings.ToLower(email),
	)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

func (s *Store) UserByID(ctx context.Context, id theauth.ULID) (*theauth.User, error) {
	row := s.db.QueryRowContext(ctx,
		selectUserColumns+` WHERE id = ?`,
		ulidToBytes(id),
	)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

func (s *Store) MarkEmailVerified(ctx context.Context, userID theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET email_verified_at = ? WHERE id = ? AND email_verified_at IS NULL`,
		timeUTC(time.Now()),
		ulidToBytes(userID),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Already verified or not found - check which
		var exists int
		if scanErr := s.db.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = ?`, ulidToBytes(userID)).Scan(&exists); errors.Is(scanErr, sql.ErrNoRows) {
			return storage.ErrNotFound
		}
	}
	return nil
}

// UserByExternalIDInOrg returns the user with external_id in the given org.
// External ID uniqueness per org is enforced at the application layer.
func (s *Store) UserByExternalIDInOrg(ctx context.Context, orgID theauth.ULID, externalID string) (*theauth.User, error) {
	row := s.db.QueryRowContext(ctx,
		selectUserColumns+`
INNER JOIN organization_members om ON om.user_id = users.id
WHERE om.organization_id = ? AND users.external_id = ?`,
		ulidToBytes(orgID), externalID,
	)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

func (s *Store) UpdateUserSCIM(ctx context.Context, u theauth.User) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE users SET
    name = ?, given_name = ?, family_name = ?, display_name = ?,
    email = ?, external_id = ?, updated_at = ?
WHERE id = ?`,
		u.Name, u.GivenName, u.FamilyName, u.DisplayName,
		strings.ToLower(u.Email), u.ExternalID,
		timeUTC(time.Now()),
		ulidToBytes(u.ID),
	)
	return err
}

func (s *Store) ListUsersByOrganization(ctx context.Context, orgID theauth.ULID, offset, limit int, filter theauth.SCIMUserFilter) ([]theauth.User, int, error) {
	if limit <= 0 {
		limit = 100
	}
	var wheres []string
	var args []interface{}
	wheres = append(wheres, "om.organization_id = ?")
	args = append(args, ulidToBytes(orgID))
	if filter.ExternalID != "" {
		wheres = append(wheres, "u.external_id = ?")
		args = append(args, filter.ExternalID)
	}
	if filter.Email != "" {
		wheres = append(wheres, "u.email = ?")
		args = append(args, strings.ToLower(filter.Email))
	}
	where := strings.Join(wheres, " AND ")
	countSQL := `SELECT COUNT(*) FROM users u INNER JOIN organization_members om ON om.user_id = u.id WHERE ` + where
	var total int
	if err := s.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	listSQL := `SELECT u.id, u.email, u.email_verified_at, u.name, u.avatar_url,
	                   u.created_at, u.updated_at, u.external_id, u.given_name, u.family_name, u.display_name
	            FROM users u
	            INNER JOIN organization_members om ON om.user_id = u.id
	            WHERE ` + where + ` ORDER BY u.created_at ASC LIMIT ? OFFSET ?`
	listArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, listSQL, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []theauth.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}
