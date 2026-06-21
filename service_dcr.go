package theauth

import (
	"context"
	"errors"

	internalas "github.com/glincker/theauth-go/internal/as"
)

// service_dcr.go: thin forwarder for RFC 7591 dynamic client
// registration. PR B architecture reorg (2026-06-20) moved the
// implementation into internal/as; the exported request type is
// re-exported as an alias so the v2.0 public surface is unchanged.

// ClientRegistrationRequest is the parsed JSON body of POST
// /oauth/register. Field names match RFC 7591 client metadata exactly
// so the wire form maps 1:1 onto the struct.
type ClientRegistrationRequest = internalas.ClientRegistrationRequest

// RegisterClient validates the request, mints a client_id (and a
// secret for confidential clients), persists the OAuthClient row, and
// returns the RFC 7591 response body. The plaintext secret is in the
// return value; callers must surface it to the caller exactly once and
// never log it.
func (a *TheAuth) RegisterClient(ctx context.Context, req ClientRegistrationRequest, anonymous bool) (RegisteredClient, error) {
	if a.as == nil {
		return RegisteredClient{}, errors.New("theauth: authorization server not configured")
	}
	return a.as.RegisterClient(ctx, req, anonymous)
}
