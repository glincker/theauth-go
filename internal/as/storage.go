// Package as implements the OAuth 2.1 and MCP authorization server runtime: JWKS and key rotation,
// the authorize, token, revoke and introspect services, dynamic client registration, RFC 8414 and
// RFC 9728 metadata, and RFC 8693 token exchange. It is internal because every public surface
// routes through *theauth.TheAuth.
package as

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// Storage is the minimal persistence subset this package needs. It is declared here to avoid
// importing the root package, which would form a cycle. The root Storage satisfies it when it also
// implements OAuthServerStorage.
type Storage interface {
	InsertOAuthClient(ctx context.Context, c models.OAuthClient) (models.OAuthClient, error)
	OAuthClientByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error)
	UpdateOAuthClient(ctx context.Context, c models.OAuthClient) (models.OAuthClient, error)
	DeleteOAuthClient(ctx context.Context, clientID string) error

	InsertAuthorizationCode(ctx context.Context, c models.AuthorizationCode) error
	ConsumeAuthorizationCode(ctx context.Context, code string) (*models.AuthorizationCode, error)

	InsertRefreshToken(ctx context.Context, t models.RefreshToken) error
	RefreshTokenByHash(ctx context.Context, hash []byte) (*models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, hash []byte, reason string) error
	RevokeRefreshTokenFamily(ctx context.Context, familyID models.ULID, reason string) error

	// JWKS keys are stored with encrypted private bytes; the storage layer does not handle the
	// encryption envelope.
	InsertJWKSKey(ctx context.Context, k models.JWKSKey) error
	JWKSKeyByKID(ctx context.Context, kid string) (*models.JWKSKey, error)
	JWKSKeysAll(ctx context.Context) ([]models.JWKSKey, error)
	UpdateJWKSKeyState(ctx context.Context, kid, state string, at time.Time) error

	// Agents are read here to check that every chain participant is still active. Lifecycle management
	// lives in the root package.
	AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error)
	AgentByClientID(ctx context.Context, clientID string) (*models.Agent, error)
	UpdateAgentLastActive(ctx context.Context, id models.ULID, at time.Time) error

	// Delegation grants are read by token exchange to authorize the actor chain, and by introspection
	// to honor revocations.
	DelegationGrantByID(ctx context.Context, id models.ULID) (*models.DelegationGrant, error)
	DelegationGrantByUserAgentResource(ctx context.Context, userID, agentID models.ULID, resource string) (*models.DelegationGrant, error)
}

// JWKSAtomicRotator is an optional capability that wraps JWKS rotation in one database transaction.
// When present, RotateSigningKey uses it instead of separate state updates, so racing rotations
// cannot leave two current rows. Implementations must retire retireKIDs, demote demoteKID to
// previous, promote promoteKID to current and insert freshKey, all or nothing.
type JWKSAtomicRotator interface {
	AtomicRotateJWKS(ctx context.Context, retireKIDs []string, demoteKID, promoteKID string, freshKey models.JWKSKey, now time.Time) error
}

// AuthCodeReplayStorage is an optional capability. When present, replaying a redeemed authorization
// code revokes every token family issued from that code first (RFC 6749 section 4.1.2). It returns
// the access token jtis that were revoked.
type AuthCodeReplayStorage interface {
	RevokeRefreshTokensByAuthCode(ctx context.Context, codeHash, reason string) ([]string, error)
}

// AccessTokenDenylistStorage backs opt-in access token revocation (Config.AccessTokenRevocation).
// Entries expire at the token's exp.
type AccessTokenDenylistStorage interface {
	DenyAccessToken(ctx context.Context, jti string, expiresAt time.Time) error
	IsAccessTokenDenied(ctx context.Context, jti string) (bool, error)
}
