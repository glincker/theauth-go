package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

// ---------- OAuth clients ----------

func (s *Store) InsertOAuthClient(ctx context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error) {
	ownerKind := clientOwnerKind(c)
	now := c.CreatedAt
	if now.IsZero() {
		now = time.Now()
	}
	updated := c.UpdatedAt
	if updated.IsZero() {
		updated = now
	}
	redirects, _ := json.Marshal(nilToEmptySlice(c.RedirectURIs))
	grants, _ := json.Marshal(nilToEmptySlice(c.GrantTypes))
	responses, _ := json.Marshal(nilToEmptySlice(c.ResponseTypes))
	contacts, _ := json.Marshal(nilToEmptySlice(c.Contacts))

	_, err := s.db.ExecContext(ctx, `
INSERT INTO oauth_clients (
    id, client_id, client_secret_hash, client_name, redirect_uris,
    grant_types, response_types, scope, token_endpoint_auth_method,
    application_type, contacts, logo_uri, policy_uri, tos_uri,
    jwks_uri, jwks, software_id, software_version, owner_kind,
    owner_user_id, owner_organization_id, owner_agent_id,
    anonymous_registered, registration_access_hash, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(c.ID),
		c.ClientID,
		nullBytesToSlice(c.ClientSecretHash),
		c.ClientName,
		redirects,
		grants,
		responses,
		c.Scope,
		defaultStr(c.TokenEndpointAuthMethod, theauth.ClientAuthSecretBasic),
		defaultStr(c.ApplicationType, "web"),
		contacts,
		c.LogoURI,
		c.PolicyURI,
		c.TosURI,
		c.JwksURI,
		nullBytesToSlice(c.Jwks),
		c.SoftwareID,
		c.SoftwareVersion,
		ownerKind,
		ulidPtrToBytes(c.Owner.UserID),
		ulidPtrToBytes(c.Owner.OrganizationID),
		ulidPtrToBytes(c.Owner.AgentID),
		boolToTinyint(c.AnonymousRegistered),
		nullBytesToSlice(c.RegistrationAccessHash),
		timeUTC(now),
		timeUTC(updated),
	)
	if err != nil {
		return theauth.OAuthClient{}, err
	}
	got, err := s.OAuthClientByClientID(ctx, c.ClientID)
	if err != nil {
		return theauth.OAuthClient{}, err
	}
	return *got, nil
}

func (s *Store) OAuthClientByClientID(ctx context.Context, clientID string) (*theauth.OAuthClient, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, client_id, client_secret_hash, client_name, redirect_uris,
       grant_types, response_types, scope, token_endpoint_auth_method,
       application_type, contacts, logo_uri, policy_uri, tos_uri,
       jwks_uri, jwks, software_id, software_version, owner_kind,
       owner_user_id, owner_organization_id, owner_agent_id,
       anonymous_registered, registration_access_hash, created_at, updated_at
FROM oauth_clients WHERE client_id = ?`, clientID)
	c, err := scanOAuthClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) UpdateOAuthClient(ctx context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error) {
	redirects, _ := json.Marshal(nilToEmptySlice(c.RedirectURIs))
	grants, _ := json.Marshal(nilToEmptySlice(c.GrantTypes))
	responses, _ := json.Marshal(nilToEmptySlice(c.ResponseTypes))
	contacts, _ := json.Marshal(nilToEmptySlice(c.Contacts))

	res, err := s.db.ExecContext(ctx, `
UPDATE oauth_clients SET
    client_name = ?, redirect_uris = ?, grant_types = ?, response_types = ?,
    scope = ?, token_endpoint_auth_method = ?, application_type = ?,
    contacts = ?, logo_uri = ?, policy_uri = ?, tos_uri = ?,
    jwks_uri = ?, jwks = ?, software_id = ?, software_version = ?,
    updated_at = ?
WHERE client_id = ?`,
		c.ClientName, redirects, grants, responses,
		c.Scope, c.TokenEndpointAuthMethod, c.ApplicationType,
		contacts, c.LogoURI, c.PolicyURI, c.TosURI,
		c.JwksURI, nullBytesToSlice(c.Jwks), c.SoftwareID, c.SoftwareVersion,
		timeUTC(time.Now()),
		c.ClientID,
	)
	if err != nil {
		return theauth.OAuthClient{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return theauth.OAuthClient{}, storage.ErrNotFound
	}
	got, err := s.OAuthClientByClientID(ctx, c.ClientID)
	if err != nil {
		return theauth.OAuthClient{}, err
	}
	return *got, nil
}

func (s *Store) DeleteOAuthClient(ctx context.Context, clientID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM oauth_clients WHERE client_id = ?`, clientID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanOAuthClient(row interface{ Scan(...interface{}) error }) (theauth.OAuthClient, error) {
	var (
		idB, ownerUserB, ownerOrgB, ownerAgentB []byte
		clientID, name, scope, authMethod       string
		appType, logo, policy, tos, jwksURI     string
		softID, softVer, ownerKind              string
		secretHash, jwks, regAccessHash         []byte
		redirectsJSON, grantsJSON               []byte
		responsesJSON, ctcsJSON                 []byte
		anonymous                               int8
		createdAt, updatedAt                    time.Time
	)
	if err := row.Scan(
		&idB, &clientID, &secretHash, &name, &redirectsJSON,
		&grantsJSON, &responsesJSON, &scope, &authMethod,
		&appType, &ctcsJSON, &logo, &policy, &tos,
		&jwksURI, &jwks, &softID, &softVer, &ownerKind,
		&ownerUserB, &ownerOrgB, &ownerAgentB,
		&anonymous, &regAccessHash, &createdAt, &updatedAt,
	); err != nil {
		return theauth.OAuthClient{}, err
	}
	var redirects, grants, responses, contacts []string
	_ = json.Unmarshal(redirectsJSON, &redirects)
	_ = json.Unmarshal(grantsJSON, &grants)
	_ = json.Unmarshal(responsesJSON, &responses)
	_ = json.Unmarshal(ctcsJSON, &contacts)

	return theauth.OAuthClient{
		ID:                      bytesToULID(idB),
		ClientID:                clientID,
		ClientSecretHash:        secretHash,
		ClientName:              name,
		RedirectURIs:            redirects,
		GrantTypes:              grants,
		ResponseTypes:           responses,
		Scope:                   scope,
		TokenEndpointAuthMethod: authMethod,
		ApplicationType:         appType,
		Contacts:                contacts,
		LogoURI:                 logo,
		PolicyURI:               policy,
		TosURI:                  tos,
		JwksURI:                 jwksURI,
		Jwks:                    jwks,
		SoftwareID:              softID,
		SoftwareVersion:         softVer,
		Owner: theauth.ClientOwner{
			UserID:         bytesToULIDPtr(ownerUserB),
			OrganizationID: bytesToULIDPtr(ownerOrgB),
			AgentID:        bytesToULIDPtr(ownerAgentB),
		},
		AnonymousRegistered:    anonymous != 0,
		RegistrationAccessHash: regAccessHash,
		CreatedAt:              createdAt.UTC(),
		UpdatedAt:              updatedAt.UTC(),
	}, nil
}

// ---------- Authorization codes ----------

func (s *Store) InsertAuthorizationCode(ctx context.Context, c theauth.AuthorizationCode) error {
	created := c.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	scopeJSON, _ := json.Marshal(nilToEmptySlice(c.Scope))
	_, err := s.db.ExecContext(ctx, `
INSERT INTO oauth_authorization_codes
    (code, client_id, user_id, organization_id, redirect_uri, scope, resource,
     code_challenge, code_challenge_method, nonce, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Code,
		c.ClientID,
		ulidToBytes(c.UserID),
		ulidPtrToBytes(c.OrganizationID),
		c.RedirectURI,
		scopeJSON,
		c.Resource,
		c.CodeChallenge,
		c.CodeChallengeMethod,
		c.Nonce,
		timeUTC(c.ExpiresAt),
		timeUTC(created),
	)
	return err
}

// ConsumeAuthorizationCode atomically loads and deletes the code row using a
// SELECT FOR UPDATE + DELETE within a transaction (MySQL has no DELETE...RETURNING).
func (s *Store) ConsumeAuthorizationCode(ctx context.Context, code string) (*theauth.AuthorizationCode, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		clientID, redirectURI, resource string
		codeChal, codeChalMethod, nonce string
		scopeJSON                       []byte
		userIDB, orgIDB                 []byte
		expiresAt, created              time.Time
	)
	err = tx.QueryRowContext(ctx, `
SELECT client_id, user_id, organization_id, redirect_uri, scope, resource,
       code_challenge, code_challenge_method, nonce, expires_at, created_at
FROM oauth_authorization_codes WHERE code = ?
FOR UPDATE`,
		code,
	).Scan(
		&clientID, &userIDB, &orgIDB, &redirectURI, &scopeJSON, &resource,
		&codeChal, &codeChalMethod, &nonce, &expiresAt, &created,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM oauth_authorization_codes WHERE code = ?`, code,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	var scope []string
	_ = json.Unmarshal(scopeJSON, &scope)

	out := &theauth.AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              bytesToULID(userIDB),
		OrganizationID:      bytesToULIDPtr(orgIDB),
		RedirectURI:         redirectURI,
		Scope:               scope,
		Resource:            resource,
		CodeChallenge:       codeChal,
		CodeChallengeMethod: codeChalMethod,
		Nonce:               nonce,
		ExpiresAt:           expiresAt.UTC(),
		CreatedAt:           created.UTC(),
	}
	return out, nil
}

// ---------- Refresh tokens ----------

func (s *Store) InsertRefreshToken(ctx context.Context, t theauth.RefreshToken) error {
	scopeJSON, _ := json.Marshal(nilToEmptySlice(t.Scope))
	_, err := s.db.ExecContext(ctx, `
INSERT INTO oauth_refresh_tokens
    (id, hash, family_id, client_id, user_id, agent_id, scope, resource,
     parent_jti, issued_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ulidToBytes(t.ID),
		t.Hash,
		ulidToBytes(t.FamilyID),
		t.ClientID,
		ulidPtrToBytes(t.UserID),
		ulidPtrToBytes(t.AgentID),
		scopeJSON,
		t.Resource,
		t.ParentJTI,
		timeUTC(t.IssuedAt),
		timeUTC(t.ExpiresAt),
	)
	return err
}

func (s *Store) RefreshTokenByHash(ctx context.Context, hash []byte) (*theauth.RefreshToken, error) {
	var (
		idB, familyIDB, userIDB, agentIDB []byte
		clientID, resource, parentJTI     string
		revNote                           string
		scopeJSON                         []byte
		issued, expires, revoked          sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, hash, family_id, client_id, user_id, agent_id, scope, resource,
       parent_jti, issued_at, expires_at, revoked_at, revocation_note
FROM oauth_refresh_tokens WHERE hash = ?`, hash,
	).Scan(
		&idB, &hash, &familyIDB, &clientID, &userIDB, &agentIDB, &scopeJSON, &resource,
		&parentJTI, &issued, &expires, &revoked, &revNote,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var scope []string
	_ = json.Unmarshal(scopeJSON, &scope)

	out := &theauth.RefreshToken{
		ID:             bytesToULID(idB),
		Hash:           hash,
		FamilyID:       bytesToULID(familyIDB),
		ClientID:       clientID,
		UserID:         bytesToULIDPtr(userIDB),
		AgentID:        bytesToULIDPtr(agentIDB),
		Scope:          scope,
		Resource:       resource,
		ParentJTI:      parentJTI,
		IssuedAt:       issued.Time.UTC(),
		ExpiresAt:      expires.Time.UTC(),
		RevokedAt:      nullTimeToPtr(revoked),
		RevocationNote: revNote,
	}
	return out, nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, hash []byte, reason string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE oauth_refresh_tokens SET revoked_at = ?, revocation_note = ?
		 WHERE hash = ? AND revoked_at IS NULL`,
		timeUTC(time.Now()), reason, hash,
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

func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID theauth.ULID, reason string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE oauth_refresh_tokens SET revoked_at = ?, revocation_note = ?
		 WHERE family_id = ? AND revoked_at IS NULL`,
		timeUTC(time.Now()), reason, ulidToBytes(familyID),
	)
	return err
}

// ---------- JWKS keys ----------

func (s *Store) InsertJWKSKey(ctx context.Context, k theauth.JWKSKey) error {
	created := k.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO jwks_keys (kid, alg, use_, public_jwk, private_enc, state, created_at, promoted_at, retired_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.KID,
		k.Alg,
		defaultStr(k.Use, "sig"),
		k.PublicJWK,
		k.PrivateEnc,
		k.State,
		timeUTC(created),
		timePtrToNull(k.PromotedAt),
		timePtrToNull(k.RetiredAt),
	)
	return err
}

func (s *Store) JWKSKeyByKID(ctx context.Context, kid string) (*theauth.JWKSKey, error) {
	k, err := scanJWKSKey(s.db.QueryRowContext(ctx, `
SELECT kid, alg, use_, public_jwk, private_enc, state, created_at, promoted_at, retired_at
FROM jwks_keys WHERE kid = ?`, kid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (s *Store) JWKSKeysAll(ctx context.Context) ([]theauth.JWKSKey, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT kid, alg, use_, public_jwk, private_enc, state, created_at, promoted_at, retired_at
FROM jwks_keys ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
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
	var err error
	switch state {
	case theauth.JWKSStateCurrent:
		_, err = s.db.ExecContext(ctx,
			`UPDATE jwks_keys SET state = ?, promoted_at = ? WHERE kid = ?`,
			state, timeUTC(at), kid)
	case theauth.JWKSStateRetired:
		_, err = s.db.ExecContext(ctx,
			`UPDATE jwks_keys SET state = ?, retired_at = ? WHERE kid = ?`,
			state, timeUTC(at), kid)
	default:
		_, err = s.db.ExecContext(ctx,
			`UPDATE jwks_keys SET state = ? WHERE kid = ?`,
			state, kid)
	}
	return err
}

func scanJWKSKey(row interface{ Scan(...interface{}) error }) (theauth.JWKSKey, error) {
	var (
		kid, alg, use, state string
		pub, priv            []byte
		created              time.Time
		promoted, retired    sql.NullTime
	)
	if err := row.Scan(&kid, &alg, &use, &pub, &priv, &state, &created, &promoted, &retired); err != nil {
		return theauth.JWKSKey{}, err
	}
	return theauth.JWKSKey{
		KID:        kid,
		Alg:        alg,
		Use:        use,
		PublicJWK:  pub,
		PrivateEnc: priv,
		State:      state,
		CreatedAt:  created.UTC(),
		PromotedAt: nullTimeToPtr(promoted),
		RetiredAt:  nullTimeToPtr(retired),
	}, nil
}

// ---------- helpers ----------

func clientOwnerKind(c theauth.OAuthClient) string {
	if c.AnonymousRegistered {
		return theauth.ClientOwnerKindAnonymous
	}
	switch {
	case c.Owner.UserID != nil:
		return theauth.ClientOwnerKindUser
	case c.Owner.OrganizationID != nil:
		return theauth.ClientOwnerKindOrganization
	case c.Owner.AgentID != nil:
		return theauth.ClientOwnerKindAgent
	}
	return theauth.ClientOwnerKindAnonymous
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func nilToEmptySlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func boolToTinyint(b bool) int8 {
	if b {
		return 1
	}
	return 0
}
