package as

import (
	"context"

	"github.com/glincker/theauth-go/v2/internal/jwt"
)

// applyOnTokenIssued runs Cfg.OnTokenIssued against the claims about to be signed and merges the
// result into claims.Extra. It runs before every access token is signed. Unlike the other lifecycle
// hooks, an error here aborts issuance, since no token exists yet.
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
