package theauth

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go/v2/internal/models"
	internaloauth "github.com/glincker/theauth-go/v2/internal/oauth"
)

// RefreshProvider is the optional Provider capability behind
// GetProviderToken. RefreshToken exchanges a refresh token for a fresh access
// token (RFC 6749 section 6). It must return an error wrapping
// ErrProviderGrantRevoked when the provider rejects the refresh token as
// invalid or revoked. The returned token's RefreshToken may be empty when
// the provider does not rotate it; the stored one is then kept. Providers
// that do not implement it keep working for sign-in; GetProviderToken
// answers ErrProviderRefreshUnsupported for them once the token expired.
type RefreshProvider = internaloauth.RefreshProvider

var (
	// ErrProviderGrantRevoked means the upstream provider no longer honors the
	// stored refresh token. The stored tokens are cleared; the user must sign
	// in with the provider again.
	ErrProviderGrantRevoked = models.ErrProviderGrantRevoked
	// ErrProviderRefreshUnsupported means the provider cannot refresh tokens
	// or no refresh token is stored for the account.
	ErrProviderRefreshUnsupported = models.ErrProviderRefreshUnsupported
	// ErrProviderNotLinked means the user has no linked account for the provider.
	ErrProviderNotLinked = models.ErrProviderNotLinked
)

// GetProviderToken returns a usable upstream access token for the user's
// linked provider account, for calling the provider's API on the user's
// behalf. The stored AES-GCM encrypted token is decrypted and returned when
// still valid; an expired one is refreshed with the stored refresh token,
// the rotated tokens are persisted, and concurrent calls for the same user
// and provider share one upstream refresh.
//
// Errors can be matched with errors.Is against ErrProviderNotLinked,
// ErrProviderRefreshUnsupported (provider cannot refresh, or no refresh
// token was granted) and ErrProviderGrantRevoked (the user revoked access;
// they must sign in with the provider again), or by TheAuthError code
// CodeProviderNoRefresh and CodeProviderGrantRevoked. It needs at least one
// configured provider and Config.EncryptionKey.
func (a *TheAuth) GetProviderToken(ctx context.Context, userID ULID, provider string) (ProviderToken, error) {
	if a.oauthSvc == nil {
		return ProviderToken{}, errors.New("theauth: no OAuth providers are configured")
	}
	return a.oauthSvc.ProviderToken(ctx, userID, provider)
}
