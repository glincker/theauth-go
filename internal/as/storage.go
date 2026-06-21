// Package as owns the OAuth 2.1 + MCP authorization server runtime: the
// JWKS state machine and key rotation goroutine, the /oauth/authorize +
// /oauth/token + /oauth/revoke + /oauth/introspect service code, dynamic
// client registration (RFC 7591), AS metadata documents (RFC 8414 +
// RFC 9728), and the RFC 8693 token-exchange grant. Extracted from the
// root package in PR B of the 2026-06 architecture reorg.
//
// The package is internal to github.com/glincker/theauth-go because every
// public API surface still routes through *theauth.TheAuth on the root
// package; the internal/as types are wired in once at TheAuth.New and
// reached via thin forwarders. Tests live in the root package as
// theauth_test and exercise the same public API, so no test code needs to
// import this package.
package as

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/internal/models"
)

// Storage is the minimal persistence subset this package needs. Declared
// here (not imported from root) so internal/as does not import
// github.com/glincker/theauth-go, which would form an import cycle with the
// root constructor.
//
// Any type satisfying these methods (notably the root theauth.Storage when
// it also implements OAuthServerStorage) is a valid argument to New. Duck
// typed against the larger root contract by design.
type Storage interface {
	// OAuth clients (RFC 7591).
	InsertOAuthClient(ctx context.Context, c models.OAuthClient) (models.OAuthClient, error)
	OAuthClientByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error)
	UpdateOAuthClient(ctx context.Context, c models.OAuthClient) (models.OAuthClient, error)
	DeleteOAuthClient(ctx context.Context, clientID string) error

	// Authorization codes (single-use, 60-second TTL).
	InsertAuthorizationCode(ctx context.Context, c models.AuthorizationCode) error
	ConsumeAuthorizationCode(ctx context.Context, code string) (*models.AuthorizationCode, error)

	// Refresh tokens (rotated on every use per RFC 9700 BCP).
	InsertRefreshToken(ctx context.Context, t models.RefreshToken) error
	RefreshTokenByHash(ctx context.Context, hash []byte) (*models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, hash []byte, reason string) error
	RevokeRefreshTokenFamily(ctx context.Context, familyID models.ULID, reason string) error

	// JWKS keys. Private bytes arrive encrypted; storage layer is unaware
	// of the encryption envelope.
	InsertJWKSKey(ctx context.Context, k models.JWKSKey) error
	JWKSKeyByKID(ctx context.Context, kid string) (*models.JWKSKey, error)
	JWKSKeysAll(ctx context.Context) ([]models.JWKSKey, error)
	UpdateJWKSKeyState(ctx context.Context, kid, state string, at time.Time) error

	// Agents (v2.0 phase 3). Used by the token-exchange and introspection
	// paths to validate that every chain participant is still active. Agent
	// lifecycle management itself lives in the root package and moves in
	// PR C.
	AgentByID(ctx context.Context, id models.ULID) (*models.Agent, error)
	AgentByClientID(ctx context.Context, clientID string) (*models.Agent, error)
	UpdateAgentLastActive(ctx context.Context, id models.ULID, at time.Time) error

	// Delegation grants (v2.0 phase 4). Used by token-exchange to authorise
	// the actor chain and by introspection to honour revocations within
	// IntrospectionCacheTTL of an operator decision.
	DelegationGrantByID(ctx context.Context, id models.ULID) (*models.DelegationGrant, error)
	DelegationGrantByUserAgentResource(ctx context.Context, userID, agentID models.ULID, resource string) (*models.DelegationGrant, error)
}
