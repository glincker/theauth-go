package sqlite

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// asServerCoreStorage is the part of theauth.OAuthServerStorage this slice
// implements: clients, authorization codes, refresh tokens and JWKS keys. The
// agent and delegation halves of that interface live in their own files, and
// the full assertion belongs there once both sets land.
type asServerCoreStorage interface {
	InsertOAuthClient(ctx context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error)
	OAuthClientByClientID(ctx context.Context, clientID string) (*theauth.OAuthClient, error)
	UpdateOAuthClient(ctx context.Context, c theauth.OAuthClient) (theauth.OAuthClient, error)
	DeleteOAuthClient(ctx context.Context, clientID string) error
	InsertAuthorizationCode(ctx context.Context, c theauth.AuthorizationCode) error
	ConsumeAuthorizationCode(ctx context.Context, code string) (*theauth.AuthorizationCode, error)
	InsertRefreshToken(ctx context.Context, t theauth.RefreshToken) error
	RefreshTokenByHash(ctx context.Context, hash []byte) (*theauth.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, hash []byte, reason string) error
	RevokeRefreshTokenFamily(ctx context.Context, familyID theauth.ULID, reason string) error
	InsertJWKSKey(ctx context.Context, k theauth.JWKSKey) error
	JWKSKeyByKID(ctx context.Context, kid string) (*theauth.JWKSKey, error)
	JWKSKeysAll(ctx context.Context) ([]theauth.JWKSKey, error)
	UpdateJWKSKeyState(ctx context.Context, kid, state string, at time.Time) error
}

// Optional authorization server capabilities the internal/as package probes
// for by duck typing: JWKS atomic rotation, authorization code replay
// revocation and the access token denylist.
type (
	asJWKSAtomicRotator interface {
		AtomicRotateJWKS(ctx context.Context, retireKIDs []string, demoteKID, promoteKID string, freshKey theauth.JWKSKey, now time.Time) error
	}
	asAuthCodeReplayStorage interface {
		RevokeRefreshTokensByAuthCode(ctx context.Context, codeHash, reason string) ([]string, error)
	}
	asAccessTokenDenylist interface {
		DenyAccessToken(ctx context.Context, jti string, expiresAt time.Time) error
		IsAccessTokenDenied(ctx context.Context, jti string) (bool, error)
	}
)

var (
	_ asServerCoreStorage                = (*Store)(nil)
	_ asJWKSAtomicRotator                = (*Store)(nil)
	_ asAuthCodeReplayStorage            = (*Store)(nil)
	_ asAccessTokenDenylist              = (*Store)(nil)
	_ theauth.OpaqueTokenStorage         = (*Store)(nil)
	_ theauth.DeviceAuthorizationStorage = (*Store)(nil)
	_ theauth.RegistrationTokenStorage   = (*Store)(nil)
)
