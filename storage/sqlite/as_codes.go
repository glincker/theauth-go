package sqlite

import (
	"context"
	"database/sql"

	"github.com/glincker/theauth-go/v2"
)

// as_codes.go: single use OAuth authorization codes over migration 0021.

const asCodeCols = `code, client_id, user_id, organization_id, redirect_uri, scope, resource,
	code_challenge, code_challenge_method, nonce, expires_at, created_at,
	authorization_details, auth_time, acr, amr`

func (s *Store) InsertAuthorizationCode(ctx context.Context, c theauth.AuthorizationCode) error {
	scope, err := asEncodeList(c.Scope)
	if err != nil {
		return wrap("insert authorization code", err)
	}
	_, err = s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_oauth_authorization_codes (`+asCodeCols+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		c.Code, c.ClientID, idStr(c.UserID), idPtrStr(c.OrganizationID), c.RedirectURI, scope, c.Resource,
		c.CodeChallenge, c.CodeChallengeMethod, c.Nonce, toMicro(c.ExpiresAt), toMicro(orNow(c.CreatedAt)),
		nullBytes(c.AuthorizationDetails), asAuthTimeArg(c.AuthTime), c.ACR, asJoinAMR(c.AMR))
	return wrap("insert authorization code", err)
}

// ConsumeAuthorizationCode implements theauth.OAuthServerStorage. A single
// DELETE ... RETURNING is the winner check: SQLite serializes writers, so
// exactly one of N concurrent callers receives the row. Expiry is left to the
// caller, as in the other backends.
func (s *Store) ConsumeAuthorizationCode(ctx context.Context, code string) (*theauth.AuthorizationCode, error) {
	var (
		out                             theauth.AuthorizationCode
		userID, scope, method, acr, amr string
		orgID                           sql.NullString
		expires, created                int64
		details                         []byte
		authAt                          sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, s.q(`
DELETE FROM theauth_oauth_authorization_codes WHERE code = ?
RETURNING `+asCodeCols), code).Scan(
		&out.Code, &out.ClientID, &userID, &orgID, &out.RedirectURI, &scope, &out.Resource,
		&out.CodeChallenge, &method, &out.Nonce, &expires, &created,
		&details, &authAt, &acr, &amr)
	if err != nil {
		return nil, notFoundOr("consume authorization code", err)
	}
	if out.UserID, err = parseID(userID); err != nil {
		return nil, wrap("consume authorization code", err)
	}
	if out.OrganizationID, err = parseIDPtr(orgID); err != nil {
		return nil, wrap("consume authorization code", err)
	}
	if out.Scope, err = asDecodeList(scope); err != nil {
		return nil, wrap("consume authorization code", err)
	}
	out.CodeChallengeMethod = method
	out.AuthorizationDetails = details
	out.AuthTime = asAuthTimeFrom(authAt)
	out.ACR = acr
	out.AMR = asSplitAMR(amr)
	out.ExpiresAt = fromMicro(expires)
	out.CreatedAt = fromMicro(created)
	return &out, nil
}
