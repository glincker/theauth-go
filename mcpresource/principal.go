package mcpresource

import (
	"context"
	"time"
)

// Principal is the parsed identity attached to every authenticated request.
// It carries both the originating subject (the user, or the root agent for a
// pure machine-to-machine call) and the final acting identity (the innermost
// agent in an RFC 8693 chain). ActorChain walks the full delegation chain
// from the innermost actor outward.
//
// For a non-delegated call (a user calling the MCP server directly, or an
// agent calling with its own client_credentials token), Subject == Actor and
// ActorChain is empty.
type Principal struct {
	// Subject is the JWT sub claim. For a delegation chain this is the
	// outermost identity (the user who granted authority), prefixed
	// "agent:" when the root is itself an agent.
	Subject string

	// Actor is the innermost acting identity. Equal to Subject when no
	// delegation chain is present. For "user -> agentA -> agentB" calls,
	// Actor is "agent:<B>" and Subject is the user ULID.
	Actor string

	// ActorChain lists the chain identities innermost to outermost. The
	// outermost element matches Subject; the innermost matches Actor. For a
	// non-delegated call, ActorChain is empty.
	ActorChain []string

	// Scope is the OAuth scope slice the token carries.
	Scope []string

	// ClientID identifies the OAuth client that obtained the token.
	ClientID string

	// IssuedAt is the JWT iat claim as a time.
	IssuedAt time.Time

	// ExpiresAt is the JWT exp claim as a time.
	ExpiresAt time.Time

	// Issuer is the JWT iss claim.
	Issuer string

	// Audience is the JWT aud claim (always equal to the configured
	// resource URI; the middleware rejects mismatches before attaching).
	Audience string

	// JWTID is the JWT jti claim.
	JWTID string

	// DelegationGrantID, when set, names the delegation_grants row that
	// authorised the innermost actor. Audit pipelines correlate every
	// failure or sensitive call back to this row.
	DelegationGrantID string

	// CnfJKT, when non-empty, is the RFC 7800 jkt confirmation
	// thumbprint that bound the access token to a DPoP key. The
	// middleware only attaches a Principal after confirming the
	// inbound DPoP proof's JWK thumbprint equals this value, so
	// handlers can trust the binding without re-verifying.
	CnfJKT string
}

// ctxKey is the unexported context key type used for principal storage.
type ctxKey struct{}

var principalCtxKey ctxKey

// withPrincipal returns a copy of ctx carrying the supplied principal.
func withPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey, p)
}

// PrincipalFromContext returns the principal attached to ctx, or false when
// no middleware ran on the request path that produced ctx. Most callers use
// (*Validator).Principal which wraps this with the validator receiver for
// API symmetry.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalCtxKey).(*Principal)
	return p, ok && p != nil
}
