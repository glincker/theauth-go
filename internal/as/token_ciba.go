package as

import (
	"context"
	"fmt"

	"github.com/glincker/theauth-go/internal/models"
)

// token_ciba.go: token minting for the CIBA grant. Splits from token.go
// to keep that file under the 500-line ceiling.

// MintCIBATokens mints the access + refresh token pair that is stored in the
// BackchannelRequest row on approval. Returns the raw access token string and
// raw refresh token string; both are stored in the BackchannelRequest.
// AccessToken is stored as a raw JWT; RefreshToken is stored as the raw opaque
// token that the client would present on /oauth/token refresh_token calls.
//
// The resource for CIBA tokens is derived from the first configured resource
// (CIBA does not carry a resource parameter on the bc-authorize request in
// Poll mode; RFC 9509 intentionally leaves scope-to-resource mapping to the
// operator). Operators that need multi-resource CIBA must add a resource hint
// field to BackchannelRequest in a future extension.
func (s *Service) MintCIBATokens(ctx context.Context, row models.BackchannelRequest, userID models.ULID) (accessToken, refreshToken string, err error) {
	if s == nil {
		return "", "", fmt.Errorf("theauth: authorization server not configured")
	}
	// Pick the first resource as the audience. If no resources are configured
	// the AS is mis-configured, but we let the JWT layer handle the empty aud.
	resource := ""
	if len(s.Cfg.Resources) > 0 {
		resource = s.Cfg.Resources[0].Identifier
	}

	uid := userID
	resp, err := s.mintAccessAndRefresh(ctx, mintInput{
		ClientID: row.ClientID,
		UserID:   &uid,
		Scope:    row.Scope,
		Resource: resource,
	})
	if err != nil {
		return "", "", err
	}
	return resp.AccessToken, resp.RefreshToken, nil
}
