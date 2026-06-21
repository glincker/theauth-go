package theauth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/crypto"
)

// AuthorizationServerConfig wires the OAuth 2.1 + MCP authorization server
// surface. Set on Config.AuthorizationServer to enable /.well-known/ and
// /oauth/ routes. Leave nil for v1.0 behavior.
//
// Phase 1 + 2 scope: authorization_code + refresh_token + revoke + introspect +
// RFC 7591 dynamic client registration + JWKS rotation. Agents, delegations,
// and RFC 8693 token exchange land in phase 3 + 4.
type AuthorizationServerConfig struct {
	// Issuer is the canonical https URL identifying this authorization server.
	// Becomes the iss claim on every issued JWT. RFC 8414 mandates no query
	// or fragment; trailing slash is stripped at New().
	Issuer string

	// Resources lists the protected resources advertised by this AS. Every
	// authorize and token request MUST carry a resource parameter that
	// matches one of these identifiers; the resulting JWT's aud claim is
	// set from the resource (RFC 8707 + RFC 9068).
	Resources []ProtectedResource

	// SigningAlg defaults to EdDSA (Ed25519). Phase 1 + 2 ships Ed25519 only.
	SigningAlg string

	// KeyRotationPeriod defaults to 30 days. The rotation goroutine promotes
	// next -> current -> previous and generates a fresh next at every cadence.
	KeyRotationPeriod time.Duration

	// KeyRetention caps how long a retired key remains visible in /oauth/jwks.
	// Defaults to 90 days.
	KeyRetention time.Duration

	// AccessTokenTTL caps the lifetime of issued access tokens. Defaults to
	// 1 hour.
	AccessTokenTTL time.Duration

	// RefreshTokenTTL caps the lifetime of refresh tokens. Defaults to 30 days.
	// Refresh tokens are rotated on every use; presenting an old token after
	// rotation revokes the family (RFC 9700 section 4.14).
	RefreshTokenTTL time.Duration

	// AuthorizationCodeTTL caps the lifetime of authorization codes. Defaults
	// to 60 seconds per OAuth 2.1 guidance.
	AuthorizationCodeTTL time.Duration

	// RegistrationAccessTokenTTL caps the lifetime of registration access
	// tokens minted on POST /oauth/register. Defaults to 365 days.
	RegistrationAccessTokenTTL time.Duration

	// AllowAnonymousRegistration permits POST /oauth/register without an
	// initial access token. Off by default. When on, the AS hard-pins the
	// endpoint to 1 request/min/IP and stamps the client row with
	// AnonymousRegistered = true for operator auditing.
	AllowAnonymousRegistration bool

	// IntrospectionCacheTTL is the Cache-Control max-age the introspection
	// endpoint emits. Defaults to 60 seconds. Resource servers may cache
	// responses up to this duration.
	IntrospectionCacheTTL time.Duration

	// LoginURL is the path on this origin where unauthenticated authorize
	// requests are redirected. Defaults to "/auth/login". The handler appends
	// a `next` query parameter with the original authorize URL.
	LoginURL string

	// DisableRotation skips the background JWKS rotation goroutine. Tests use
	// this to assert key state from a known fixture; production must leave
	// it false.
	DisableRotation bool
}

// ProtectedResource describes one resource server protected by this AS. The
// Identifier appears in the aud claim of issued tokens; it MUST be the URL the
// resource server advertises in its own /.well-known/oauth-protected-resource
// document.
type ProtectedResource struct {
	Identifier  string
	DisplayName string
	Scopes      []string
}

// asState bundles the runtime state of the authorization server. Held on
// TheAuth.as when AuthorizationServer is configured.
type asState struct {
	cfg     AuthorizationServerConfig
	storage OAuthServerStorage

	// signingKeys is the in-memory snapshot of the JWKS state machine. The
	// rotation goroutine swaps it atomically under mu.
	mu     sync.RWMutex
	keys   []JWKSKey // ordered: current first, then next, then previous, then retired (filtered out of JWKS)
	keyMap map[string]JWKSKey

	rotationStop chan struct{}
	rotationDone chan struct{}

	// introspectCache memoizes recent introspection responses keyed by token
	// hash. Honors IntrospectionCacheTTL.
	introspectCache sync.Map // map[string]*introspectCacheEntry
}

type introspectCacheEntry struct {
	expiresAt time.Time
	body      []byte
}

// validateASConfig applies defaults and screens required fields.
func validateASConfig(cfg *AuthorizationServerConfig, encryptionKey []byte) error {
	if cfg == nil {
		return nil
	}
	if cfg.Issuer == "" {
		return ErrASIssuerRequired
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if len(encryptionKey) != crypto.AESKeyLen {
		return ErrASRequiresEncryptionKey
	}
	if cfg.SigningAlg == "" {
		cfg.SigningAlg = "EdDSA"
	}
	if cfg.SigningAlg != "EdDSA" {
		return ErrASUnsupportedAlg
	}
	if cfg.KeyRotationPeriod <= 0 {
		cfg.KeyRotationPeriod = 30 * 24 * time.Hour
	}
	if cfg.KeyRetention <= 0 {
		cfg.KeyRetention = 90 * 24 * time.Hour
	}
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = time.Hour
	}
	if cfg.RefreshTokenTTL <= 0 {
		cfg.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if cfg.AuthorizationCodeTTL <= 0 {
		cfg.AuthorizationCodeTTL = 60 * time.Second
	}
	if cfg.RegistrationAccessTokenTTL <= 0 {
		cfg.RegistrationAccessTokenTTL = 365 * 24 * time.Hour
	}
	if cfg.IntrospectionCacheTTL <= 0 {
		cfg.IntrospectionCacheTTL = 60 * time.Second
	}
	if cfg.LoginURL == "" {
		cfg.LoginURL = "/auth/login"
	}
	return nil
}

// startAS bootstraps the JWKS state (loading existing keys or minting fresh
// ones) and launches the rotation goroutine when DisableRotation is false.
func (a *TheAuth) startAS(ctx context.Context) error {
	if a.as == nil {
		return nil
	}
	if err := a.bootstrapJWKS(ctx); err != nil {
		return err
	}
	if a.as.cfg.DisableRotation {
		return nil
	}
	a.as.rotationStop = make(chan struct{})
	a.as.rotationDone = make(chan struct{})
	go a.jwksRotationLoop()
	return nil
}

// stopAS shuts the rotation goroutine and waits for it to finish.
func (a *TheAuth) stopAS() {
	if a.as == nil || a.as.rotationStop == nil {
		return
	}
	select {
	case <-a.as.rotationStop:
		// already closed
	default:
		close(a.as.rotationStop)
	}
	if a.as.rotationDone != nil {
		select {
		case <-a.as.rotationDone:
		case <-time.After(5 * time.Second):
			slog.Warn("theauth: JWKS rotation goroutine did not drain in 5s")
		}
	}
}

// resourceByIdentifier returns the configured ProtectedResource matching the
// supplied identifier, or false when not found. Identifier matching is case
// sensitive and trims a single trailing slash on the input to absorb caller
// inconsistency.
func (a *TheAuth) resourceByIdentifier(id string) (ProtectedResource, bool) {
	if a.as == nil {
		return ProtectedResource{}, false
	}
	id = strings.TrimRight(id, "/")
	for _, r := range a.as.cfg.Resources {
		canonical := strings.TrimRight(r.Identifier, "/")
		if canonical == id {
			return r, true
		}
	}
	return ProtectedResource{}, false
}

// validateScopeAgainstResource returns the intersection of requested and
// supported scopes; returns error if requested contains any scope outside
// the resource's catalog.
func validateScopeAgainstResource(requested []string, resource ProtectedResource) ([]string, error) {
	if len(requested) == 0 {
		return nil, errors.New("scope required")
	}
	if len(resource.Scopes) == 0 {
		return requested, nil
	}
	supported := map[string]struct{}{}
	for _, s := range resource.Scopes {
		supported[s] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	for _, s := range requested {
		if _, ok := supported[s]; !ok {
			return nil, ErrOAuthInvalidScope
		}
		out = append(out, s)
	}
	return out, nil
}

// scopeIntersection returns the intersection of two scope slices, preserving
// order from `a`. Used at refresh time to ensure narrowing requests stay
// within the original grant.
func scopeIntersection(a, b []string) []string {
	have := map[string]struct{}{}
	for _, s := range b {
		have[s] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, s := range a {
		if _, ok := have[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// scopeSubset reports whether every element of sub is present in sup.
func scopeSubset(sub, sup []string) bool {
	have := map[string]struct{}{}
	for _, s := range sup {
		have[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := have[s]; !ok {
			return false
		}
	}
	return true
}

// scopeJoin renders a scope slice as the space-separated form used in JWT
// claims, RFC 7591 client metadata, and Cache-Control responses.
func scopeJoin(scope []string) string { return strings.Join(scope, " ") }

// scopeSplit parses a space-separated scope string into a deduped slice
// preserving order of first occurrence.
func scopeSplit(s string) []string {
	parts := strings.Fields(s)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
