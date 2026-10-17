package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// as_clients.go: OAuth client storage (RFC 7591 registrations and operator
// created clients) over migration 0020.

const asClientCols = `id, client_id, client_secret_hash, client_name, redirect_uris,
	grant_types, response_types, scope, token_endpoint_auth_method,
	application_type, contacts, logo_uri, policy_uri, tos_uri,
	jwks_uri, jwks, software_id, software_version, owner_kind,
	owner_user_id, owner_organization_id, owner_agent_id,
	anonymous_registered, registration_access_hash, created_at, updated_at,
	access_token_format, access_token_signed_response_alg, authorization_details_types,
	oidc_metadata`

func asClientOwnerKind(c theauth.OAuthClient) string {
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

func asBoolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// asClientLists encodes the five JSON list columns of a client.
func asClientLists(c theauth.OAuthClient) (redirects, grants, responses, contacts, detailTypes string, err error) {
	if redirects, err = asEncodeList(c.RedirectURIs); err != nil {
		return
	}
	if grants, err = asEncodeList(c.GrantTypes); err != nil {
		return
	}
	if responses, err = asEncodeList(c.ResponseTypes); err != nil {
		return
	}
	if contacts, err = asEncodeList(c.Contacts); err != nil {
		return
	}
	detailTypes, err = asEncodeList(c.AuthorizationDetailsTypes)
	return
}

// InsertOAuthClient implements theauth.OAuthServerStorage.
func (s *Store) InsertOAuthClient(ctx context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error) {
	redirects, grants, responses, contacts, detailTypes, err := asClientLists(c)
	if err != nil {
		return theauth.OAuthClient{}, wrap("insert oauth client", err)
	}
	created := orNow(c.CreatedAt)
	updated := c.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	_, err = s.db.ExecContext(ctx, s.q(`
INSERT INTO theauth_oauth_clients (`+asClientCols+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		idStr(c.ID), c.ClientID, nullBytes(c.ClientSecretHash), c.ClientName, redirects,
		grants, responses, c.Scope, asDefault(c.TokenEndpointAuthMethod, theauth.ClientAuthSecretBasic),
		asDefault(c.ApplicationType, "web"), contacts, c.LogoURI, c.PolicyURI, c.TosURI,
		c.JwksURI, nullBytes(c.Jwks), c.SoftwareID, c.SoftwareVersion, asClientOwnerKind(c),
		idPtrStr(c.Owner.UserID), idPtrStr(c.Owner.OrganizationID), idPtrStr(c.Owner.AgentID),
		asBoolInt(c.AnonymousRegistered), nullBytes(c.RegistrationAccessHash), toMicro(created), toMicro(updated),
		c.AccessTokenFormat, c.AccessTokenSignedResponseAlg, detailTypes,
		string(c.OIDCMetadataJSON()))
	if err != nil {
		return theauth.OAuthClient{}, wrap("insert oauth client", err)
	}
	c.CreatedAt = fromMicro(toMicro(created))
	c.UpdatedAt = fromMicro(toMicro(updated))
	return c, nil
}

func asScanClient(r scanner) (theauth.OAuthClient, error) {
	var (
		id, clientID, name, scope, authMethod, appType, logo, policy, tos string
		jwksURI, softID, softVer, ownerKind, tokenFormat, tokenAlg        string
		redirects, grants, responses, contacts, detailTypes, oidcMeta     string
		secretHash, jwks, regAccessHash                                   []byte
		ownerUser, ownerOrg, ownerAgent                                   sql.NullString
		anonymous                                                         int
		created, updated                                                  int64
	)
	if err := r.Scan(&id, &clientID, &secretHash, &name, &redirects,
		&grants, &responses, &scope, &authMethod,
		&appType, &contacts, &logo, &policy, &tos,
		&jwksURI, &jwks, &softID, &softVer, &ownerKind,
		&ownerUser, &ownerOrg, &ownerAgent,
		&anonymous, &regAccessHash, &created, &updated,
		&tokenFormat, &tokenAlg, &detailTypes, &oidcMeta); err != nil {
		return theauth.OAuthClient{}, err
	}
	uid, err := parseID(id)
	if err != nil {
		return theauth.OAuthClient{}, err
	}
	out := theauth.OAuthClient{
		ID: uid, ClientID: clientID, ClientSecretHash: secretHash, ClientName: name,
		Scope: scope, TokenEndpointAuthMethod: authMethod, ApplicationType: appType,
		LogoURI: logo, PolicyURI: policy, TosURI: tos, JwksURI: jwksURI, Jwks: jwks,
		SoftwareID: softID, SoftwareVersion: softVer,
		AccessTokenFormat: tokenFormat, AccessTokenSignedResponseAlg: tokenAlg,
		AnonymousRegistered: anonymous != 0, RegistrationAccessHash: regAccessHash,
		CreatedAt: fromMicro(created), UpdatedAt: fromMicro(updated),
	}
	if out.RedirectURIs, err = asDecodeList(redirects); err != nil {
		return theauth.OAuthClient{}, err
	}
	if out.GrantTypes, err = asDecodeList(grants); err != nil {
		return theauth.OAuthClient{}, err
	}
	if out.ResponseTypes, err = asDecodeList(responses); err != nil {
		return theauth.OAuthClient{}, err
	}
	if out.Contacts, err = asDecodeList(contacts); err != nil {
		return theauth.OAuthClient{}, err
	}
	if out.AuthorizationDetailsTypes, err = asDecodeList(detailTypes); err != nil {
		return theauth.OAuthClient{}, err
	}
	if out.Owner.UserID, err = parseIDPtr(ownerUser); err != nil {
		return theauth.OAuthClient{}, err
	}
	if out.Owner.OrganizationID, err = parseIDPtr(ownerOrg); err != nil {
		return theauth.OAuthClient{}, err
	}
	if out.Owner.AgentID, err = parseIDPtr(ownerAgent); err != nil {
		return theauth.OAuthClient{}, err
	}
	out.SetOIDCMetadataJSON([]byte(oidcMeta))
	return out, nil
}

// OAuthClientByClientID implements theauth.OAuthServerStorage.
func (s *Store) OAuthClientByClientID(ctx context.Context, clientID string) (*theauth.OAuthClient, error) {
	c, err := asScanClient(s.db.QueryRowContext(ctx, s.q(
		`SELECT `+asClientCols+` FROM theauth_oauth_clients WHERE client_id = ?`), clientID))
	if err != nil {
		return nil, notFoundOr("oauth client by client id", err)
	}
	return &c, nil
}

// UpdateOAuthClient implements theauth.OAuthServerStorage. Owner, secret hash
// and creation time are immutable here, matching the other backends.
func (s *Store) UpdateOAuthClient(ctx context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error) {
	redirects, grants, responses, contacts, detailTypes, err := asClientLists(c)
	if err != nil {
		return theauth.OAuthClient{}, wrap("update oauth client", err)
	}
	now := time.Now()
	res, err := s.db.ExecContext(ctx, s.q(`
UPDATE theauth_oauth_clients SET
	client_name = ?, redirect_uris = ?, grant_types = ?, response_types = ?,
	scope = ?, token_endpoint_auth_method = ?, application_type = ?,
	contacts = ?, logo_uri = ?, policy_uri = ?, tos_uri = ?,
	jwks_uri = ?, jwks = ?, software_id = ?, software_version = ?,
	access_token_format = ?, access_token_signed_response_alg = ?,
	authorization_details_types = ?, oidc_metadata = ?, updated_at = ?
WHERE client_id = ?`),
		c.ClientName, redirects, grants, responses,
		c.Scope, c.TokenEndpointAuthMethod, c.ApplicationType,
		contacts, c.LogoURI, c.PolicyURI, c.TosURI,
		c.JwksURI, nullBytes(c.Jwks), c.SoftwareID, c.SoftwareVersion,
		c.AccessTokenFormat, c.AccessTokenSignedResponseAlg,
		detailTypes, string(c.OIDCMetadataJSON()), toMicro(now), c.ClientID)
	if err != nil {
		return theauth.OAuthClient{}, wrap("update oauth client", err)
	}
	if err := requireRows("update oauth client", res); err != nil {
		return theauth.OAuthClient{}, err
	}
	c.UpdatedAt = fromMicro(toMicro(now))
	return c, nil
}

// DeleteOAuthClient implements theauth.OAuthServerStorage. The 0029 trigger
// removes the client's codes and tokens in the same statement.
func (s *Store) DeleteOAuthClient(ctx context.Context, clientID string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM theauth_oauth_clients WHERE client_id = ?`), clientID)
	if err != nil {
		return wrap("delete oauth client", err)
	}
	return requireRows("delete oauth client", res)
}
