package postgres

import (
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/jackc/pgx/v5/pgtype"
)

// postgres_v20_helpers.go: scan helpers and pure mapping extracted from postgres_v20.go for the LOC budget.

// pgRowScanner is the subset of pgx.Row / pgx.Rows used by the scan helpers.
type pgRowScanner interface {
	Scan(dest ...any) error
}

// nilToDefault returns def when s is empty, so the NOT NULL DEFAULT column is satisfied on INSERT.
func nilToDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// nonNilBytes returns an empty, non-nil slice for nil so pgx writes an empty bytea
// instead of NULL into a NOT NULL bytea column.
func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// nullableBytes returns nil for an empty slice so pgx writes NULL rather than an empty bytea.
func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// emptyIfNilStrings returns an empty slice for nil so pgx writes '{}' rather than SQL NULL, which
// would violate NOT NULL even with a column default.
func emptyIfNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// clientOwnerKindFor derives owner_kind from the owner fields. Clients with no owner fall into
// "anonymous" to satisfy the CHECK constraint.
func clientOwnerKindFor(c theauth.OAuthClient) string {
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

func scanOAuthClient(row pgRowScanner) (theauth.OAuthClient, error) {
	var (
		id, ownerUser, ownerOrg, ownerAgent pgtype.UUID
		clientID, name, scope, authMethod   string
		appType, logo, policy, tos, jwksURI string
		softID, softVer, ownerKind          string
		secretHash, jwks, regAccessHash     []byte
		redirects, grants, responses, ctcs  []string
		anonymous                           bool
		createdAt, updatedAt                pgtype.Timestamptz
		tokenFormat, tokenAlg               string
		detailTypes                         []string
		oidcMeta                            string
	)
	if err := row.Scan(
		&id, &clientID, &secretHash, &name, &redirects,
		&grants, &responses, &scope, &authMethod,
		&appType, &ctcs, &logo, &policy, &tos,
		&jwksURI, &jwks, &softID, &softVer, &ownerKind,
		&ownerUser, &ownerOrg, &ownerAgent,
		&anonymous, &regAccessHash, &createdAt, &updatedAt,
		&tokenFormat, &tokenAlg, &detailTypes, &oidcMeta,
	); err != nil {
		return theauth.OAuthClient{}, err
	}
	out := theauth.OAuthClient{
		ID:                      pgUUIDToULID(id),
		ClientID:                clientID,
		ClientSecretHash:        secretHash,
		ClientName:              name,
		RedirectURIs:            redirects,
		GrantTypes:              grants,
		ResponseTypes:           responses,
		Scope:                   scope,
		TokenEndpointAuthMethod: authMethod,
		ApplicationType:         appType,
		Contacts:                ctcs,
		LogoURI:                 logo,
		PolicyURI:               policy,
		TosURI:                  tos,
		JwksURI:                 jwksURI,
		Jwks:                    jwks,
		SoftwareID:              softID,
		SoftwareVersion:         softVer,

		AccessTokenFormat:            tokenFormat,
		AccessTokenSignedResponseAlg: tokenAlg,
		AuthorizationDetailsTypes:    detailTypes,
		Owner: theauth.ClientOwner{
			UserID:         pgUUIDToULIDPtr(ownerUser),
			OrganizationID: pgUUIDToULIDPtr(ownerOrg),
			AgentID:        pgUUIDToULIDPtr(ownerAgent),
		},
		AnonymousRegistered:    anonymous,
		RegistrationAccessHash: regAccessHash,
		CreatedAt:              tsToTime(createdAt),
		UpdatedAt:              tsToTime(updatedAt),
	}
	out.SetOIDCMetadataJSON([]byte(oidcMeta))
	return out, nil
}

func scanJWKSKey(row pgRowScanner) (theauth.JWKSKey, error) {
	var (
		kid, alg, use, state       string
		pub, priv                  []byte
		created, promoted, retired pgtype.Timestamptz
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
		CreatedAt:  tsToTime(created),
		PromotedAt: tsToTimePtr(promoted),
		RetiredAt:  tsToTimePtr(retired),
	}, nil
}

// authTimeToTs maps the zero time to SQL NULL (no authentication time recorded).
func authTimeToTs(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func authTimeFromTs(ts pgtype.Timestamptz) time.Time {
	if !ts.Valid {
		return time.Time{}
	}
	return ts.Time
}
