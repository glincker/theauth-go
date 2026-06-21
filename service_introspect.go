package theauth

import (
	"context"
	"errors"

	internalas "github.com/glincker/theauth-go/internal/as"
)

// service_introspect.go: thin forwarder for RFC 7662 token
// introspection. PR B architecture reorg (2026-06-20) moved the
// implementation into internal/as; the exported response type is
// re-exported as an alias so the v2.0 public surface is unchanged.

// IntrospectionResponse mirrors the JSON shape mandated by RFC 7662
// section 2.2 plus the v2.0 act chain and delegation_grant_id
// forward-compatibility fields.
type IntrospectionResponse = internalas.IntrospectionResponse

// IntrospectToken validates the supplied token and returns the
// structured introspection response. Token type detection: JWTs are
// recognised by the three dot-separated base64 segments; everything
// else is treated as a refresh token (looked up by hash).
//
// Audience binding: when expectedAud is non-empty (resource server
// passes its own identifier), tokens with a mismatching aud return
// active=false.
func (a *TheAuth) IntrospectToken(ctx context.Context, token, clientID, clientSecret, expectedAud string) (IntrospectionResponse, []byte, error) {
	if a.as == nil {
		return IntrospectionResponse{}, nil, errors.New("theauth: authorization server not configured")
	}
	return a.as.IntrospectToken(ctx, token, clientID, clientSecret, expectedAud)
}
