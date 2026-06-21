package theauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/clientauthcache"
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

	// RegistrationTokens is the operator-supplied set of bearer initial
	// access tokens that POST /oauth/register accepts when DCR is bearer
	// gated (the default). Each entry is the raw token string; it is
	// sha256-hashed at New time and the plaintext is dropped, so the
	// in-memory state never carries the secret value. Token comparisons
	// run under crypto/subtle.ConstantTimeCompare so token-presence
	// timing is not observable.
	//
	// When AllowAnonymousRegistration is false (the default and the
	// production-recommended value) and RegistrationTokens is empty,
	// POST /oauth/register returns 401 access_denied to every caller,
	// because no operator-issued token can possibly match. Operators
	// that want a truly open DCR endpoint must flip
	// AllowAnonymousRegistration to true explicitly (security audit H1,
	// 2026-06-20).
	RegistrationTokens []string

	// RegistrationRateLimitPerMinute caps POST /oauth/register at this
	// many requests per source IP per minute. Defaults: 1 when
	// AllowAnonymousRegistration is true (matches the documented public
	// MCP profile), 5 otherwise. Set to a negative value to disable the
	// per-IP cap entirely (operator opt-out; not recommended on a
	// public-internet bind) (security audit H2, 2026-06-20).
	RegistrationRateLimitPerMinute int

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

// ProtectedResource is now defined in internal/models and re-exported from
// models_v20.go as a type alias. The struct definition was relocated as
// part of the arch-A0 models extraction so that every persistent and
// configuration entity lives in one package.

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
	// privKeyByKID holds the AES-GCM-decrypted ed25519.PrivateKey for every
	// active key in keyMap. Populated by refreshJWKSSnapshot at boot, at
	// every scheduled rotation tick, and at every manual RotateSigningKey
	// call. Consumed by currentSigningKey under mu.RLock so the JWT mint
	// path never re-runs aes.NewCipher + cipher.NewGCM on the hot path.
	//
	// Cache invalidation contract: this map is REPLACED wholesale (not
	// mutated in place) by refreshJWKSSnapshot. Because every key state
	// transition (bootstrap, scheduled rotation, manual RotateSigningKey)
	// ends with a refreshJWKSSnapshot call, a rotated or retired KID is
	// automatically gone from this cache the moment the public keyMap
	// stops listing it. There is no external invalidation surface; the
	// snapshot owns the lifecycle.
	privKeyByKID map[string]ed25519.PrivateKey

	rotationStop chan struct{}
	rotationDone chan struct{}

	// introspectCache memoizes recent introspection responses keyed by token
	// hash. Honors IntrospectionCacheTTL.
	introspectCache sync.Map // map[string]*introspectCacheEntry

	// clientAuthCache memoizes the result of an Argon2id verify on
	// client_secret_hash. Keyed by client_id; cached entries bind the
	// verified *OAuthClient snapshot to the sha256 of the presented
	// secret.
	//
	// Cache invalidation contract: invalidateClientAuthCache(clientID)
	// MUST be called from every path that rotates or removes the stored
	// client_secret_hash. The current call sites are:
	//   - service_agent.go::MintAgentCredential (rotates via
	//     storage.UpdateOAuthClient).
	//   - service_agent.go::CreateAgent failure-cleanup (deletes via
	//     storage.DeleteOAuthClient).
	// Bounded LRU + 5 minute TTL prevent unbounded memory growth and cap
	// the window during which a stale entry could survive an external
	// secret rotation.
	clientAuthCache *clientauthcache.Cache[*OAuthClient]
}

type introspectCacheEntry struct {
	expiresAt time.Time
	body      []byte
}

// invalidateClientAuthCache drops the cached Argon2-verified entry for
// clientID. Called from every code path that rotates or removes the
// stored client_secret_hash so a freshly minted secret is never shadowed
// by a stale verified entry and a deleted client cannot continue
// authenticating from cache.
func (a *TheAuth) invalidateClientAuthCache(clientID string) {
	if a == nil || a.as == nil || a.as.clientAuthCache == nil {
		return
	}
	a.as.clientAuthCache.Invalidate(clientID)
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
	// security audit H2 (2026-06-20): documented per-IP cap is now
	// enforced. Defaults match the docstring on AllowAnonymousRegistration:
	// 1 req/min/IP for the anonymous public-MCP profile, 5 req/min/IP for
	// the bearer-gated profile. Operators that need different limits set
	// RegistrationRateLimitPerMinute explicitly; a negative value disables
	// the cap.
	if cfg.RegistrationRateLimitPerMinute == 0 {
		if cfg.AllowAnonymousRegistration {
			cfg.RegistrationRateLimitPerMinute = 1
		} else {
			cfg.RegistrationRateLimitPerMinute = 5
		}
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
