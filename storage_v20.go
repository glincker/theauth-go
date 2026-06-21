package theauth

import (
	"context"
	"errors"
	"time"
)

// v2.0 (phase 1 + 2) storage extension interface.
//
// Backward compatibility: the root Storage interface is unchanged. The
// authorization server (Config.AuthorizationServer != nil) requires the
// configured storage to also satisfy OAuthServerStorage. New() type-asserts
// and returns ErrStorageMissingOAuthMethods when the assertion fails, so
// pre-v2.0 storage adapters keep compiling for non-AS deployments.
//
// The in-tree memory and postgres adapters satisfy OAuthServerStorage out of
// the box; consumers running custom adapters need to add the methods below
// before they can enable Config.AuthorizationServer.

// OAuthServerStorage is the subset of persistence required by the OAuth 2.1
// authorization server, the JWKS rotation goroutine, and dynamic client
// registration. Phase 1 + 2 only. Agent and delegation methods land in
// phase 3 + 4 alongside the corresponding service code.
type OAuthServerStorage interface {
	// OAuth clients (RFC 7591).
	InsertOAuthClient(ctx context.Context, c OAuthClient) (OAuthClient, error)
	OAuthClientByClientID(ctx context.Context, clientID string) (*OAuthClient, error)
	UpdateOAuthClient(ctx context.Context, c OAuthClient) (OAuthClient, error)
	DeleteOAuthClient(ctx context.Context, clientID string) error

	// Authorization codes (single-use, 60-second TTL).
	InsertAuthorizationCode(ctx context.Context, c AuthorizationCode) error
	// ConsumeAuthorizationCode atomically loads-and-deletes a code row,
	// returning it. ErrStorageNotFound when absent or already consumed.
	ConsumeAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)

	// Refresh tokens (rotated on every use per RFC 9700 BCP).
	InsertRefreshToken(ctx context.Context, t RefreshToken) error
	RefreshTokenByHash(ctx context.Context, hash []byte) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, hash []byte, reason string) error
	RevokeRefreshTokenFamily(ctx context.Context, familyID ULID, reason string) error

	// JWKS keys. Private bytes arrive encrypted; storage layer is unaware of
	// the encryption envelope.
	InsertJWKSKey(ctx context.Context, k JWKSKey) error
	JWKSKeyByKID(ctx context.Context, kid string) (*JWKSKey, error)
	JWKSKeysAll(ctx context.Context) ([]JWKSKey, error)
	UpdateJWKSKeyState(ctx context.Context, kid, state string, at time.Time) error
}

// ErrStorageMissingOAuthMethods is returned by New when
// Config.AuthorizationServer is non-nil but Config.Storage does not satisfy
// OAuthServerStorage.
var ErrStorageMissingOAuthMethods = errors.New("theauth: Storage must implement OAuthServerStorage when AuthorizationServer is configured")
