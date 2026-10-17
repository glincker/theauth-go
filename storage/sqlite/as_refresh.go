package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// as_refresh.go: rotating refresh tokens, token family revocation, code replay
// revocation and the access token denylist over migrations 0022 and 0023.

const asRefreshCols = `id, hash, family_id, client_id, user_id, agent_id, scope, resource,
	parent_jti, issued_at, expires_at, revoked_at, revocation_note,
	dpop_jkt, auth_code_hash, authorization_details, auth_time, acr, amr`

func (s *Store) InsertRefreshToken(ctx context.Context, t theauth.RefreshToken) error {
	scope, err := asEncodeList(t.Scope)
	if err != nil {
		return wrap("insert refresh token", err)
	}
	_, err = s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_oauth_refresh_tokens (
	id, hash, family_id, client_id, user_id, agent_id, scope, resource,
	parent_jti, issued_at, expires_at, dpop_jkt, auth_code_hash, authorization_details,
	auth_time, acr, amr
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		idStr(t.ID), t.Hash, idStr(t.FamilyID), t.ClientID, idPtrStr(t.UserID), idPtrStr(t.AgentID),
		scope, t.Resource, t.ParentJTI, toMicro(t.IssuedAt), toMicro(t.ExpiresAt), t.DPoPJKT, t.AuthCodeHash,
		nullBytes(t.AuthorizationDetails), asAuthTimeArg(t.AuthTime), t.ACR, asJoinAMR(t.AMR))
	return wrap("insert refresh token", err)
}

func (s *Store) RefreshTokenByHash(ctx context.Context, hash []byte) (*theauth.RefreshToken, error) {
	var (
		id, familyID, clientID, scope, resource, parentJTI, note string
		dpopJKT, authCodeHash, acr, amr                          string
		userID, agentID                                          sql.NullString
		hashOut, details                                         []byte
		issued, expires                                          int64
		revoked, authAt                                          sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, s.q(
		`SELECT `+asRefreshCols+` FROM theauth_oauth_refresh_tokens WHERE hash = ?`), hash).Scan(
		&id, &hashOut, &familyID, &clientID, &userID, &agentID, &scope, &resource,
		&parentJTI, &issued, &expires, &revoked, &note,
		&dpopJKT, &authCodeHash, &details, &authAt, &acr, &amr)
	if err != nil {
		return nil, notFoundOr("refresh token by hash", err)
	}
	out := theauth.RefreshToken{
		Hash: hashOut, ClientID: clientID, Resource: resource, ParentJTI: parentJTI,
		IssuedAt: fromMicro(issued), ExpiresAt: fromMicro(expires), RevokedAt: fromNullMicro(revoked),
		RevocationNote: note, DPoPJKT: dpopJKT, AuthCodeHash: authCodeHash,
		AuthorizationDetails: details, AuthTime: asAuthTimeFrom(authAt), ACR: acr, AMR: asSplitAMR(amr),
	}
	if out.ID, err = parseID(id); err != nil {
		return nil, wrap("refresh token by hash", err)
	}
	if out.FamilyID, err = parseID(familyID); err != nil {
		return nil, wrap("refresh token by hash", err)
	}
	if out.UserID, err = parseIDPtr(userID); err != nil {
		return nil, wrap("refresh token by hash", err)
	}
	if out.AgentID, err = parseIDPtr(agentID); err != nil {
		return nil, wrap("refresh token by hash", err)
	}
	if out.Scope, err = asDecodeList(scope); err != nil {
		return nil, wrap("refresh token by hash", err)
	}
	return &out, nil
}

// RevokeRefreshToken implements theauth.OAuthServerStorage. It is the rotation gate: exactly
// one caller wins per token; a replay or concurrent refresh gets ErrStorageNotFound.
func (s *Store) RevokeRefreshToken(ctx context.Context, hash []byte, reason string) error {
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_oauth_refresh_tokens SET revoked_at = ?, revocation_note = ?
WHERE hash = ? AND revoked_at IS NULL`), toMicro(time.Now()), reason, hash)
	if err != nil {
		return wrap("revoke refresh token", err)
	}
	return requireRows("revoke refresh token", res)
}

// RevokeRefreshTokenFamily implements theauth.OAuthServerStorage. Revoking a
// family with no live tokens is not an error.
func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID theauth.ULID, reason string) error {
	_, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_oauth_refresh_tokens SET revoked_at = ?, revocation_note = ?
WHERE family_id = ? AND revoked_at IS NULL`), toMicro(time.Now()), reason, idStr(familyID))
	return wrap("revoke refresh token family", err)
}

// RevokeRefreshTokensByAuthCode revokes every live token issued from the code stored under
// codeHash (RFC 6749 4.1.2 code replay) and returns their access token jtis, in one statement.
func (s *Store) RevokeRefreshTokensByAuthCode(ctx context.Context, codeHash, reason string) ([]string, error) {
	if codeHash == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, s.q(`
UPDATE theauth_oauth_refresh_tokens SET revoked_at = ?, revocation_note = ?
WHERE revoked_at IS NULL AND family_id IN (
	SELECT family_id FROM theauth_oauth_refresh_tokens WHERE auth_code_hash = ?
)
RETURNING parent_jti`), toMicro(time.Now()), reason, codeHash)
	if err != nil {
		return nil, wrap("revoke refresh tokens by auth code", err)
	}
	defer func() { _ = rows.Close() }()
	var jtis []string
	for rows.Next() {
		var j string
		if err := rows.Scan(&j); err != nil {
			return nil, wrap("revoke refresh tokens by auth code", err)
		}
		jtis = append(jtis, j)
	}
	return jtis, wrap("revoke refresh tokens by auth code", rows.Err())
}

// DenyAccessToken records jti as revoked until expiresAt (opt-in access token
// revocation) and opportunistically purges entries that have lapsed.
func (s *Store) DenyAccessToken(ctx context.Context, jti string, expiresAt time.Time) error {
	if _, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_oauth_revoked_jtis (jti, expires_at) VALUES (?, ?)
ON CONFLICT (jti) DO UPDATE SET expires_at = excluded.expires_at`), jti, toMicro(expiresAt)); err != nil {
		return wrap("deny access token", err)
	}
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM theauth_oauth_revoked_jtis WHERE expires_at < ?`), toMicro(time.Now()))
	return nil
}

// IsAccessTokenDenied reports whether jti is on the unexpired denylist.
func (s *Store) IsAccessTokenDenied(ctx context.Context, jti string) (bool, error) {
	var denied bool
	err := s.db.QueryRowContext(ctx, s.q(
		`SELECT EXISTS (SELECT 1 FROM theauth_oauth_revoked_jtis WHERE jti = ? AND expires_at > ?)`),
		jti, toMicro(time.Now())).Scan(&denied)
	return denied, wrap("is access token denied", err)
}
