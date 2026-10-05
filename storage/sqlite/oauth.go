package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go"
)

const oauthCols = `id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc,
	expires_at, scope, created_at, updated_at`

func scanOAuthAccount(r scanner) (theauth.OAuthAccount, error) {
	var (
		id, userID, provider, provUser, scope string
		access, refresh                       []byte
		expires                               sql.NullInt64
		created, updated                      int64
	)
	if err := r.Scan(&id, &userID, &provider, &provUser, &access, &refresh, &expires, &scope, &created, &updated); err != nil {
		return theauth.OAuthAccount{}, err
	}
	aid, err := parseID(id)
	if err != nil {
		return theauth.OAuthAccount{}, err
	}
	uid, err := parseID(userID)
	if err != nil {
		return theauth.OAuthAccount{}, err
	}
	return theauth.OAuthAccount{
		ID: aid, UserID: uid, Provider: provider, ProviderUserID: provUser,
		AccessTokenEnc: access, RefreshTokenEnc: refresh,
		ExpiresAt: fromNullMicro(expires), Scope: scope,
		CreatedAt: fromMicro(created), UpdatedAt: fromMicro(updated),
	}, nil
}

// UpsertOAuthAccount inserts or refreshes the tokens of a (provider, provider user) pair.
func (s *Store) UpsertOAuthAccount(ctx context.Context, a theauth.OAuthAccount) (theauth.OAuthAccount, error) {
	created := orNow(a.CreatedAt)
	updated := a.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	row := s.db.QueryRowContext(ctx, s.q(`
INSERT INTO theauth_oauth_accounts (`+oauthCols+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (provider, provider_user_id) DO UPDATE SET
	access_token_enc  = excluded.access_token_enc,
	refresh_token_enc = excluded.refresh_token_enc,
	expires_at        = excluded.expires_at,
	scope             = excluded.scope,
	updated_at        = excluded.updated_at
RETURNING `+oauthCols),
		idStr(a.ID), idStr(a.UserID), a.Provider, a.ProviderUserID,
		nonNilBytes(a.AccessTokenEnc), nullBytes(a.RefreshTokenEnc),
		toNullMicro(a.ExpiresAt), a.Scope, toMicro(created), toMicro(updated))
	out, err := scanOAuthAccount(row)
	if err != nil {
		return theauth.OAuthAccount{}, wrap("upsert oauth account", err)
	}
	return out, nil
}

// OAuthAccountByProviderUserID looks up a linked account by its provider identity.
func (s *Store) OAuthAccountByProviderUserID(ctx context.Context, provider, providerUserID string) (*theauth.OAuthAccount, error) {
	a, err := scanOAuthAccount(s.db.QueryRowContext(ctx, s.q(
		`SELECT `+oauthCols+` FROM theauth_oauth_accounts WHERE provider = ? AND provider_user_id = ?`),
		provider, providerUserID))
	if err != nil {
		return nil, notFoundOr("oauth account by provider user id", err)
	}
	return &a, nil
}

// OAuthAccountsByUserID lists a user's linked accounts, empty when there are none.
func (s *Store) OAuthAccountsByUserID(ctx context.Context, userID theauth.ULID) ([]theauth.OAuthAccount, error) {
	rows, err := s.db.QueryContext(ctx, s.q(
		`SELECT `+oauthCols+` FROM theauth_oauth_accounts WHERE user_id = ? ORDER BY created_at, id`), idStr(userID))
	if err != nil {
		return nil, wrap("oauth accounts by user id", err)
	}
	defer func() { _ = rows.Close() }()
	out := []theauth.OAuthAccount{}
	for rows.Next() {
		a, err := scanOAuthAccount(rows)
		if err != nil {
			return nil, wrap("oauth accounts by user id", err)
		}
		out = append(out, a)
	}
	return out, wrap("oauth accounts by user id", rows.Err())
}

// MoveOAuthAccount reassigns a linked account to newUserID.
func (s *Store) MoveOAuthAccount(ctx context.Context, provider, providerUserID string, newUserID theauth.ULID) error {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_oauth_accounts SET user_id = ?, updated_at = ?
WHERE provider = ? AND provider_user_id = ?`),
		idStr(newUserID), toMicro(time.Now()), provider, providerUserID)
	if err != nil {
		return wrap("move oauth account", err)
	}
	return requireRows("move oauth account", res)
}

// DeleteOAuthAccountByProvider unlinks a user's account for one provider.
func (s *Store) DeleteOAuthAccountByProvider(ctx context.Context, userID theauth.ULID, provider string) error {
	res, err := s.db.ExecContext(ctx,
		s.q(`DELETE FROM theauth_oauth_accounts WHERE user_id = ? AND provider = ?`), idStr(userID), provider)
	if err != nil {
		return wrap("delete oauth account", err)
	}
	return requireRows("delete oauth account", res)
}
