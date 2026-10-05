package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go"
)

const userCols = `id, email, email_verified_at, name, avatar_url, created_at, updated_at,
	external_id, given_name, family_name, display_name`

func scanUser(r scanner) (theauth.User, error) {
	var (
		id                      string
		email                   string
		verified                sql.NullInt64
		name, avatar            string
		created, updated        int64
		ext, given, family, dsp string
	)
	if err := r.Scan(&id, &email, &verified, &name, &avatar, &created, &updated, &ext, &given, &family, &dsp); err != nil {
		return theauth.User{}, err
	}
	uid, err := parseID(id)
	if err != nil {
		return theauth.User{}, err
	}
	return theauth.User{
		ID:              uid,
		Email:           email,
		EmailVerifiedAt: fromNullMicro(verified),
		Name:            name,
		AvatarURL:       avatar,
		CreatedAt:       fromMicro(created),
		UpdatedAt:       fromMicro(updated),
		ExternalID:      ext,
		GivenName:       given,
		FamilyName:      family,
		DisplayName:     dsp,
	}, nil
}

// CreateUser inserts u and returns the stored row. Email uniqueness is case-insensitive.
func (s *Store) CreateUser(ctx context.Context, u theauth.User) (theauth.User, error) {
	created := orNow(u.CreatedAt)
	updated := u.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	row := s.db.QueryRowContext(ctx, s.q(`
INSERT INTO theauth_users (id, email, email_verified_at, name, avatar_url, created_at, updated_at,
	external_id, given_name, family_name, display_name)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING `+userCols),
		idStr(u.ID), u.Email, toNullMicro(u.EmailVerifiedAt), u.Name, u.AvatarURL,
		toMicro(created), toMicro(updated),
		u.ExternalID, u.GivenName, u.FamilyName, u.DisplayName,
	)
	out, err := scanUser(row)
	if err != nil {
		return theauth.User{}, wrap("create user", err)
	}
	return out, nil
}

// UserByEmail returns the user with the given email, compared case-insensitively.
func (s *Store) UserByEmail(ctx context.Context, email string) (*theauth.User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+userCols+` FROM theauth_users WHERE email = ?`), email))
	if err != nil {
		return nil, notFoundOr("user by email", err)
	}
	return &u, nil
}

// UserByID returns the user with the given ID.
func (s *Store) UserByID(ctx context.Context, id theauth.ULID) (*theauth.User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx,
		s.q(`SELECT `+userCols+` FROM theauth_users WHERE id = ?`), idStr(id)))
	if err != nil {
		return nil, notFoundOr("user by id", err)
	}
	return &u, nil
}

// MarkEmailVerified sets the verification time once and keeps the first value on repeat calls.
func (s *Store) MarkEmailVerified(ctx context.Context, userID theauth.ULID) error {
	now := toMicro(time.Now())
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_users SET email_verified_at = COALESCE(email_verified_at, ?), updated_at = ?
WHERE id = ?`), now, now, idStr(userID))
	if err != nil {
		return wrap("mark email verified", err)
	}
	return requireRows("mark email verified", res)
}
