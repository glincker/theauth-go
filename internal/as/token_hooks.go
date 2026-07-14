package as

import (
	"context"

	"github.com/glincker/theauth-go/internal/jwt"
)

// applyOnTokenIssued runs Cfg.OnTokenIssued (when set) against the claims
// about to be signed into an access token JWT, merging the returned map
// into claims.Extra. Called from every access-token minting path
// (authorization_code, refresh_token, client_credentials, RFC 8693 token
// exchange) immediately before jwt.Sign.
//
// Unlike every other LifecycleHooks callback, a non-nil error here aborts
// issuance: the token has not been minted yet, so there is nothing to roll
// back and no reason to swallow the error.
func (s *Service) applyOnTokenIssued(ctx context.Context, claims *jwt.Claims) error {
	if s.Cfg.OnTokenIssued == nil {
		return nil
	}
	in := map[string]any{
		"iss":       claims.Iss,
		"sub":       claims.Sub,
		"aud":       claims.Aud,
		"exp":       claims.Exp,
		"iat":       claims.Iat,
		"jti":       claims.Jti,
		"client_id": claims.ClientID,
		"scope":     claims.Scope,
	}
	for k, v := range claims.Extra {
		in[k] = v
	}
	out, err := s.Cfg.OnTokenIssued(ctx, in)
	if err != nil {
		return err
	}
	if claims.Extra == nil {
		claims.Extra = make(map[string]any, len(out))
	}
	for k, v := range out {
		claims.Extra[k] = v
	}
	return nil
}
