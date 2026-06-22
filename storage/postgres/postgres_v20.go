package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// v2.0 (phase 1 + 2): Postgres adapter for the OAuth 2.1 authorization
// server tables introduced by migrations 0011 to 0014. Queries are hand
// rolled against pgx/v5 to keep this PR self contained; sqlc regeneration
// for these tables is deferred (the existing sqlc directory stays untouched).

// ---------- OAuth clients ----------

func (s *Store) InsertOAuthClient(ctx context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error) {
	const q = `
INSERT INTO oauth_clients (
  id, client_id, client_secret_hash, client_name, redirect_uris,
  grant_types, response_types, scope, token_endpoint_auth_method,
  application_type, contacts, logo_uri, policy_uri, tos_uri,
  jwks_uri, jwks, software_id, software_version, owner_kind,
  owner_user_id, owner_organization_id, owner_agent_id,
  anonymous_registered, registration_access_hash, created_at, updated_at
) VALUES (
  $1, $2, $3, $4, $5,
  $6, $7, $8, $9,
  $10, $11, $12, $13, $14,
  $15, $16, $17, $18, $19,
  $20, $21, $22,
  $23, $24, $25, $26
)
RETURNING client_id, created_at, updated_at`
	ownerKind := clientOwnerKindFor(c)
	now := c.CreatedAt
	if now.IsZero() {
		now = time.Now()
	}
	updated := c.UpdatedAt
	if updated.IsZero() {
		updated = now
	}
	row := s.pool.QueryRow(ctx, q,
		ulidToPgUUID(c.ID),
		c.ClientID,
		nullableBytes(c.ClientSecretHash),
		c.ClientName,
		emptyIfNilStrings(c.RedirectURIs),
		emptyIfNilStrings(c.GrantTypes),
		emptyIfNilStrings(c.ResponseTypes),
		c.Scope,
		nilToDefault(c.TokenEndpointAuthMethod, theauth.ClientAuthSecretBasic),
		nilToDefault(c.ApplicationType, "web"),
		emptyIfNilStrings(c.Contacts),
		c.LogoURI,
		c.PolicyURI,
		c.TosURI,
		c.JwksURI,
		nullableBytes(c.Jwks),
		c.SoftwareID,
		c.SoftwareVersion,
		ownerKind,
		ulidPtrToPgUUID(c.Owner.UserID),
		ulidPtrToPgUUID(c.Owner.OrganizationID),
		ulidPtrToPgUUID(c.Owner.AgentID),
		c.AnonymousRegistered,
		nullableBytes(c.RegistrationAccessHash),
		timeToTs(now),
		timeToTs(updated),
	)
	var clientID string
	var createdAt, updatedAt pgtype.Timestamptz
	if err := row.Scan(&clientID, &createdAt, &updatedAt); err != nil {
		return theauth.OAuthClient{}, err
	}
	c.ClientID = clientID
	c.CreatedAt = tsToTime(createdAt)
	c.UpdatedAt = tsToTime(updatedAt)
	return c, nil
}

func (s *Store) OAuthClientByClientID(ctx context.Context, clientID string) (*theauth.OAuthClient, error) {
	const q = `
SELECT id, client_id, client_secret_hash, client_name, redirect_uris,
       grant_types, response_types, scope, token_endpoint_auth_method,
       application_type, contacts, logo_uri, policy_uri, tos_uri,
       jwks_uri, jwks, software_id, software_version, owner_kind,
       owner_user_id, owner_organization_id, owner_agent_id,
       anonymous_registered, registration_access_hash, created_at, updated_at
FROM oauth_clients WHERE client_id = $1`
	c, err := scanOAuthClient(s.pool.QueryRow(ctx, q, clientID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

func (s *Store) UpdateOAuthClient(ctx context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error) {
	const q = `
UPDATE oauth_clients SET
  client_name = $2, redirect_uris = $3, grant_types = $4, response_types = $5,
  scope = $6, token_endpoint_auth_method = $7, application_type = $8,
  contacts = $9, logo_uri = $10, policy_uri = $11, tos_uri = $12,
  jwks_uri = $13, jwks = $14, software_id = $15, software_version = $16,
  updated_at = now()
WHERE client_id = $1
RETURNING updated_at`
	row := s.pool.QueryRow(ctx, q,
		c.ClientID,
		c.ClientName,
		emptyIfNilStrings(c.RedirectURIs),
		emptyIfNilStrings(c.GrantTypes),
		emptyIfNilStrings(c.ResponseTypes),
		c.Scope,
		c.TokenEndpointAuthMethod,
		c.ApplicationType,
		emptyIfNilStrings(c.Contacts),
		c.LogoURI,
		c.PolicyURI,
		c.TosURI,
		c.JwksURI,
		nullableBytes(c.Jwks),
		c.SoftwareID,
		c.SoftwareVersion,
	)
	var updatedAt pgtype.Timestamptz
	if err := row.Scan(&updatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return theauth.OAuthClient{}, storage.ErrNotFound
		}
		return theauth.OAuthClient{}, err
	}
	c.UpdatedAt = tsToTime(updatedAt)
	return c, nil
}

func (s *Store) DeleteOAuthClient(ctx context.Context, clientID string) error {
	const q = `DELETE FROM oauth_clients WHERE client_id = $1`
	tag, err := s.pool.Exec(ctx, q, clientID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// ---------- authorization codes ----------

func (s *Store) InsertAuthorizationCode(ctx context.Context, c theauth.AuthorizationCode) error {
	const q = `
INSERT INTO oauth_authorization_codes (
  code, client_id, user_id, organization_id, redirect_uri, scope, resource,
  code_challenge, code_challenge_method, nonce, expires_at, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	created := c.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err := s.pool.Exec(ctx, q,
		c.Code,
		c.ClientID,
		ulidToPgUUID(c.UserID),
		ulidPtrToPgUUID(c.OrganizationID),
		c.RedirectURI,
		c.Scope,
		c.Resource,
		c.CodeChallenge,
		c.CodeChallengeMethod,
		c.Nonce,
		timeToTs(c.ExpiresAt),
		timeToTs(created),
	)
	return err
}

// ConsumeAuthorizationCode uses DELETE ... RETURNING for atomicity: exactly
// one of N concurrent callers wins per code.
func (s *Store) ConsumeAuthorizationCode(ctx context.Context, code string) (*theauth.AuthorizationCode, error) {
	const q = `
DELETE FROM oauth_authorization_codes
WHERE code = $1
RETURNING code, client_id, user_id, organization_id, redirect_uri, scope, resource,
          code_challenge, code_challenge_method, nonce, expires_at, created_at`
	row := s.pool.QueryRow(ctx, q, code)
	var (
		out     theauth.AuthorizationCode
		userID  pgtype.UUID
		orgID   pgtype.UUID
		expires pgtype.Timestamptz
		created pgtype.Timestamptz
		scope   []string
		nonce   string
		method  string
	)
	err := row.Scan(
		&out.Code,
		&out.ClientID,
		&userID,
		&orgID,
		&out.RedirectURI,
		&scope,
		&out.Resource,
		&out.CodeChallenge,
		&method,
		&nonce,
		&expires,
		&created,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	out.UserID = pgUUIDToULID(userID)
	out.OrganizationID = pgUUIDToULIDPtr(orgID)
	out.Scope = scope
	out.Nonce = nonce
	out.CodeChallengeMethod = method
	out.ExpiresAt = tsToTime(expires)
	out.CreatedAt = tsToTime(created)
	return &out, nil
}

// ---------- refresh tokens ----------

func (s *Store) InsertRefreshToken(ctx context.Context, t theauth.RefreshToken) error {
	const q = `
INSERT INTO oauth_refresh_tokens (
  id, hash, family_id, client_id, user_id, agent_id, scope, resource,
  parent_jti, issued_at, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := s.pool.Exec(ctx, q,
		ulidToPgUUID(t.ID),
		t.Hash,
		ulidToPgUUID(t.FamilyID),
		t.ClientID,
		ulidPtrToPgUUID(t.UserID),
		ulidPtrToPgUUID(t.AgentID),
		t.Scope,
		t.Resource,
		t.ParentJTI,
		timeToTs(t.IssuedAt),
		timeToTs(t.ExpiresAt),
	)
	return err
}

func (s *Store) RefreshTokenByHash(ctx context.Context, hash []byte) (*theauth.RefreshToken, error) {
	const q = `
SELECT id, hash, family_id, client_id, user_id, agent_id, scope, resource,
       parent_jti, issued_at, expires_at, revoked_at, revocation_note
FROM oauth_refresh_tokens WHERE hash = $1`
	row := s.pool.QueryRow(ctx, q, hash)
	var (
		id, familyID              pgtype.UUID
		userID, agentID           pgtype.UUID
		issued, expires           pgtype.Timestamptz
		revoked                   pgtype.Timestamptz
		parentJTI, resource, note string
		hashOut                   []byte
		scope                     []string
		clientID                  string
	)
	err := row.Scan(&id, &hashOut, &familyID, &clientID, &userID, &agentID,
		&scope, &resource, &parentJTI, &issued, &expires, &revoked, &note)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	out := theauth.RefreshToken{
		ID:             pgUUIDToULID(id),
		Hash:           hashOut,
		FamilyID:       pgUUIDToULID(familyID),
		ClientID:       clientID,
		UserID:         pgUUIDToULIDPtr(userID),
		AgentID:        pgUUIDToULIDPtr(agentID),
		Scope:          scope,
		Resource:       resource,
		ParentJTI:      parentJTI,
		IssuedAt:       tsToTime(issued),
		ExpiresAt:      tsToTime(expires),
		RevokedAt:      tsToTimePtr(revoked),
		RevocationNote: note,
	}
	return &out, nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, hash []byte, reason string) error {
	const q = `UPDATE oauth_refresh_tokens SET revoked_at = now(), revocation_note = $2 WHERE hash = $1 AND revoked_at IS NULL`
	tag, err := s.pool.Exec(ctx, q, hash, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID theauth.ULID, reason string) error {
	const q = `UPDATE oauth_refresh_tokens SET revoked_at = now(), revocation_note = $2 WHERE family_id = $1 AND revoked_at IS NULL`
	_, err := s.pool.Exec(ctx, q, ulidToPgUUID(familyID), reason)
	return err
}

// ---------- JWKS ----------

func (s *Store) InsertJWKSKey(ctx context.Context, k theauth.JWKSKey) error {
	const q = `
INSERT INTO jwks_keys (kid, alg, use_, public_jwk, private_enc, state, created_at, promoted_at, retired_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	created := k.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err := s.pool.Exec(ctx, q,
		k.KID,
		k.Alg,
		nilToDefault(k.Use, "sig"),
		k.PublicJWK,
		k.PrivateEnc,
		k.State,
		timeToTs(created),
		timePtrToTs(k.PromotedAt),
		timePtrToTs(k.RetiredAt),
	)
	return err
}

func (s *Store) JWKSKeyByKID(ctx context.Context, kid string) (*theauth.JWKSKey, error) {
	const q = `SELECT kid, alg, use_, public_jwk, private_enc, state, created_at, promoted_at, retired_at
FROM jwks_keys WHERE kid = $1`
	row := s.pool.QueryRow(ctx, q, kid)
	k, err := scanJWKSKey(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return &k, nil
}

func (s *Store) JWKSKeysAll(ctx context.Context) ([]theauth.JWKSKey, error) {
	const q = `SELECT kid, alg, use_, public_jwk, private_enc, state, created_at, promoted_at, retired_at
FROM jwks_keys ORDER BY created_at ASC`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []theauth.JWKSKey
	for rows.Next() {
		k, err := scanJWKSKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) UpdateJWKSKeyState(ctx context.Context, kid, state string, at time.Time) error {
	var q string
	switch state {
	case theauth.JWKSStateCurrent:
		q = `UPDATE jwks_keys SET state = $2, promoted_at = $3 WHERE kid = $1`
	case theauth.JWKSStateRetired:
		q = `UPDATE jwks_keys SET state = $2, retired_at = $3 WHERE kid = $1`
	default:
		q = `UPDATE jwks_keys SET state = $2 WHERE kid = $1`
		_, err := s.pool.Exec(ctx, q, kid, state)
		return err
	}
	_, err := s.pool.Exec(ctx, q, kid, state, timeToTs(at))
	return err
}

// scan helpers + small mapping utilities live in postgres_v20_helpers.go to
// keep this file under the 500 LOC budget.
