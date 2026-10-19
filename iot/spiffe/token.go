package spiffe

import (
	"context"
	"errors"

	theauth "github.com/glincker/theauth-go/v2"
)

// ErrNoKeyBinding is returned by IssueToken for a result that has no certificate to bind to. A
// JWT-SVID carries no key the holder proves possession of, so it never gets a bound token.
var ErrNoKeyBinding = errors.New("spiffe: only an X.509-SVID result can be exchanged for a certificate bound token")

// TokenIssuer mints certificate bound device tokens. *theauth.TheAuth satisfies it.
type TokenIssuer interface {
	IssueDeviceCertToken(ctx context.Context, req theauth.DeviceCertTokenRequest) (theauth.TokenResponse, error)
}

// IssueToken exchanges a verified X.509-SVID result for an RFC 8705 certificate bound access token:
// the token carries cnf x5t#S256 of the SVID leaf, so a resource server accepts it only on a TLS
// connection that presents that certificate (mcpresource enforces this). The token lives no longer
// than the SVID. res must come from AuthenticateX509 or AuthenticatePEM on a chain whose leaf key
// the peer proved it holds, normally a client certificate from a completed mutual TLS handshake.
// resource and scope pick the audience and narrow the device's scopes, as on the assertion grant.
func (b *Bridge) IssueToken(ctx context.Context, issuer TokenIssuer, res *Result, resource string, scope []string) (theauth.TokenResponse, error) {
	if res == nil || res.Kind != "x509" || res.CNF["x5t#S256"] == "" {
		return theauth.TokenResponse{}, ErrNoKeyBinding
	}
	return issuer.IssueDeviceCertToken(ctx, theauth.DeviceCertTokenRequest{
		DeviceID: res.Device.ID,
		X5tS256:  res.CNF["x5t#S256"],
		Resource: resource,
		Scope:    scope,
		NotAfter: res.ExpiresAt,
	})
}
