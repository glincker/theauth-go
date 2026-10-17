package theauth

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go/v2/internal/models"
	internaloauth "github.com/glincker/theauth-go/v2/internal/oauth"
)

// RefreshProvider is the optional Provider capability behind GetProviderToken. It must return an
// error wrapping ErrProviderGrantRevoked when the provider rejects the refresh token. Providers
// without it still sign users in; GetProviderToken answers ErrProviderRefreshUnsupported once their
// token expires.
type RefreshProvider = internaloauth.RefreshProvider

var (
	// ErrProviderGrantRevoked means the provider no longer honors the stored refresh token. The stored
	// tokens are cleared.
	ErrProviderGrantRevoked = models.ErrProviderGrantRevoked
	// ErrProviderRefreshUnsupported means the provider cannot refresh, or no refresh token is stored.
	ErrProviderRefreshUnsupported = models.ErrProviderRefreshUnsupported
	// ErrProviderNotLinked means the user has no linked account for the provider.
	ErrProviderNotLinked = models.ErrProviderNotLinked
)

// GetProviderToken returns a usable upstream access token for the user's linked provider account.
// An expired token is refreshed and the rotated tokens persisted; concurrent calls for one user and
// provider share one upstream refresh. It needs at least one configured provider and
// Config.EncryptionKey.
func (a *TheAuth) GetProviderToken(ctx context.Context, userID ULID, provider string) (ProviderToken, error) {
	if a.oauthSvc == nil {
		return ProviderToken{}, errors.New("theauth: no OAuth providers are configured")
	}
	return a.oauthSvc.ProviderToken(ctx, userID, provider)
}
