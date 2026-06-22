package postgres

import (
	"github.com/glincker/theauth-go"
	"github.com/jackc/pgx/v5/pgtype"
)

// postgres_v20_helpers.go: scan helpers + small adapters extracted from
// postgres_v20.go to keep that file under the 500 LOC budget. No logic
// belongs here that touches a pool; this file is pure mapping.

// pgRowScanner is the subset of pgx.Row / pgx.Rows used by the scan helpers.
type pgRowScanner interface {
	Scan(dest ...any) error
}

// nilToDefault returns def when s is empty, otherwise s. Used at INSERT time
// so a zero-valued field still satisfies the migration's NOT NULL DEFAULT
// constraint when the caller omits it.
func nilToDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// nullableBytes returns nil for an empty slice so pgx encodes NULL rather
// than an empty bytea. Caller passes the result as an any argument.
func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// emptyIfNilStrings returns an empty slice when s is nil so pgx encodes an
// empty text[] rather than SQL NULL. Used at INSERT/UPDATE time for columns
// declared text[] NOT NULL with a column default of '{}'. A nil Go slice
// passes through pgx as SQL NULL and violates the NOT NULL constraint even
// when a column default is present, because explicit NULL overrides defaults.
func emptyIfNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// clientOwnerKindFor derives the owner_kind column value from the owner
// pointer triplet plus the anonymous flag. Falls back to "anonymous" when
// no owner is set; bearer-gated DCR clients without an explicit owner land
// in this bucket so the migration's CHECK constraint is satisfied.
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
	)
	if err := row.Scan(
		&id, &clientID, &secretHash, &name, &redirects,
		&grants, &responses, &scope, &authMethod,
		&appType, &ctcs, &logo, &policy, &tos,
		&jwksURI, &jwks, &softID, &softVer, &ownerKind,
		&ownerUser, &ownerOrg, &ownerAgent,
		&anonymous, &regAccessHash, &createdAt, &updatedAt,
	); err != nil {
		return theauth.OAuthClient{}, err
	}
	return theauth.OAuthClient{
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
		Owner: theauth.ClientOwner{
			UserID:         pgUUIDToULIDPtr(ownerUser),
			OrganizationID: pgUUIDToULIDPtr(ownerOrg),
			AgentID:        pgUUIDToULIDPtr(ownerAgent),
		},
		AnonymousRegistered:    anonymous,
		RegistrationAccessHash: regAccessHash,
		CreatedAt:              tsToTime(createdAt),
		UpdatedAt:              tsToTime(updatedAt),
	}, nil
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
