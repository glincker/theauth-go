package sqlite

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// asServerCoreStorage is the core part of theauth.OAuthServerStorage: clients, codes, refresh tokens and JWKS keys.
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

// Optional capabilities probed by duck typing in internal/as: atomic JWKS rotation, code replay
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
