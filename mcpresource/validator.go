package mcpresource

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Validator is the request-time gatekeeper for an MCP resource server. Build
// it once with New and reuse it for every request; the underlying JWKS and
// introspection caches are concurrency safe.
type Validator struct {
	resourceURI string

	jwksURI string

	introspectURI    string
	introspectClient string
	introspectSecret string

	cacheTTL time.Duration

	httpClient *http.Client

	clockSkew time.Duration

	jwks       *jwksCache
	introspect *introspectCache

	// dpop, when non-nil, enables RFC 9449 sender-constrained access
	// token validation. A token carrying cnf.jkt requires an inbound
	// DPoP header matching the claim; absence of cnf.jkt falls back to
	// Bearer-token semantics.
	dpop          *dpopVerifier
	dpopEnabled   bool
	dpopAllowAlgs []string
	dpopMaxAge    time.Duration
	dpopJTIWindow int

	startOnce sync.Once
}

// Option configures a Validator built via New.
type Option func(*Validator)

// WithJWKS sets the URL the validator fetches signing keys from. The cache
// refreshes on first request, again on a kid miss, and again at most once per
// WithCacheTTL window thereafter.
func WithJWKS(jwksURI string) Option {
	return func(v *Validator) { v.jwksURI = jwksURI }
}

// WithIntrospection wires the AS introspection endpoint and the client
// credentials the validator uses to call it. The validator authenticates with
// HTTP Basic per RFC 7662 section 2.1.
func WithIntrospection(introspectURI, clientID, clientSecret string) Option {
	return func(v *Validator) {
		v.introspectURI = introspectURI
		v.introspectClient = clientID
		v.introspectSecret = clientSecret
	}
}

// WithCacheTTL overrides the default 60-second JWKS + introspection cache
// window. Lower values trade extra AS round trips for faster revocation
// propagation; higher values do the opposite. The MCP authorization spec
// caps practical TTLs at a few minutes.
func WithCacheTTL(d time.Duration) Option {
	return func(v *Validator) {
		if d > 0 {
			v.cacheTTL = d
		}
	}
}

// WithHTTPClient injects an http.Client used for JWKS and introspection
// fetches. The default uses http.DefaultClient with a 10 second timeout
// override; pass a configured client when the resource server runs behind a
// proxy or needs custom transport hooks.
func WithHTTPClient(c *http.Client) Option {
	return func(v *Validator) {
		if c != nil {
			v.httpClient = c
		}
	}
}

// WithClockSkew overrides the default 60 second skew tolerance applied to
// exp, nbf, and iat checks.
func WithClockSkew(d time.Duration) Option {
	return func(v *Validator) {
		if d > 0 {
			v.clockSkew = d
		}
	}
}

// WithDPoPVerification enables RFC 9449 sender-constrained access token
// validation. When set, the middleware extracts the inbound DPoP header
// and, for every access token carrying an RFC 7800 cnf.jkt claim,
// REQUIRES the proof key thumbprint to equal cnf.jkt. Tokens without
// cnf.jkt continue to be accepted as plain Bearer tokens; the AS
// chooses per-token whether to constrain.
//
// allowedSignAlgs defaults to ES256, ES384, RS256, PS256, EdDSA. Set
// proofMaxAge to bound clock skew on the proof iat claim (default 60s).
// jtiReplayWindow caps the in-memory replay LRU (default 4096).
func WithDPoPVerification(allowedSignAlgs []string, proofMaxAge time.Duration, jtiReplayWindow int) Option {
	return func(v *Validator) {
		v.dpopEnabled = true
		v.dpopAllowAlgs = append([]string(nil), allowedSignAlgs...)
		v.dpopMaxAge = proofMaxAge
		v.dpopJTIWindow = jtiReplayWindow
	}
}

// New constructs a Validator. The resourceURI MUST match the aud claim of
// every accepted token; it is also the URL the AS advertises in its
// /.well-known/oauth-protected-resource document. The configuration is
// validated lazily: a missing JWKS URL surfaces only on the first request.
func New(resourceURI string, opts ...Option) *Validator {
	v := &Validator{
		resourceURI: resourceURI,
		cacheTTL:    60 * time.Second,
		clockSkew:   60 * time.Second,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(v)
	}
	v.jwks = newJWKSCache(v.jwksURI, v.httpClient, v.cacheTTL)
	v.introspect = newIntrospectCache(v.introspectURI, v.introspectClient, v.introspectSecret, v.httpClient, v.cacheTTL)
	if v.dpopEnabled {
		v.dpop = newDPoPVerifier(v.dpopAllowAlgs, v.dpopMaxAge, v.clockSkew, v.dpopJTIWindow)
	}
	return v
}

// ResourceURI returns the resource identifier this validator enforces. Used by
// the protected-resource discovery handler and test fixtures.
func (v *Validator) ResourceURI() string { return v.resourceURI }

// CacheTTL reports the configured cache window for tests and operators.
func (v *Validator) CacheTTL() time.Duration { return v.cacheTTL }

// Principal returns the principal attached to ctx by the middleware. The bool
// is false when no token has been validated on the request path that produced
// ctx (for example when Principal is called from a handler that bypassed the
// middleware).
func (v *Validator) Principal(ctx context.Context) (*Principal, bool) {
	return PrincipalFromContext(ctx)
}

// errInvalidConfig is returned by validate() when the validator is missing
// the JWKS URL or other required wiring.
var errInvalidConfig = errors.New("mcpresource: validator missing JWKS URL")

// validateConfig surfaces wiring errors before the first request lands.
func (v *Validator) validateConfig() error {
	if v.resourceURI == "" {
		return errors.New("mcpresource: resourceURI required")
	}
	if v.jwksURI == "" {
		return errInvalidConfig
	}
	return nil
}
