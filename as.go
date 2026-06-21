package theauth

import (
	"time"

	internalas "github.com/glincker/theauth-go/internal/as"
)

// as.go: AuthorizationServerConfig declaration plus the thin forwarders
// that consolidate the small helpers historically attached to the *asState
// struct. PR B architecture reorg (2026-06-20) moved the runtime
// implementation to internal/as; the struct + asConfigFromRoot at the
// bottom of theauth.go preserve the wire shape and the New() defaults.

// AuthorizationServerConfig wires the OAuth 2.1 + MCP authorization
// server surface. Set on Config.AuthorizationServer to enable
// /.well-known/ and /oauth/ routes. Leave nil for v1.0 behavior.
//
// Phase 1 + 2 scope: authorization_code + refresh_token + revoke +
// introspect + RFC 7591 dynamic client registration + JWKS rotation.
// Agents, delegations, and RFC 8693 token exchange land in phase 3 + 4.
type AuthorizationServerConfig struct {
	// Issuer is the canonical https URL identifying this authorization
	// server. Becomes the iss claim on every issued JWT. RFC 8414
	// mandates no query or fragment; trailing slash is stripped at New().
	Issuer string

	// Resources lists the protected resources advertised by this AS.
	// Every authorize and token request MUST carry a resource parameter
	// that matches one of these identifiers; the resulting JWT's aud
	// claim is set from the resource (RFC 8707 + RFC 9068).
	Resources []ProtectedResource

	// SigningAlg defaults to EdDSA (Ed25519). Phase 1 + 2 ships Ed25519
	// only.
	SigningAlg string

	// KeyRotationPeriod defaults to 30 days. The rotation goroutine
	// promotes next -> current -> previous and generates a fresh next at
	// every cadence.
	KeyRotationPeriod time.Duration

	// KeyRetention caps how long a retired key remains visible in
	// /oauth/jwks. Defaults to 90 days.
	KeyRetention time.Duration

	// AccessTokenTTL caps the lifetime of issued access tokens. Defaults
	// to 1 hour.
	AccessTokenTTL time.Duration

	// RefreshTokenTTL caps the lifetime of refresh tokens. Defaults to 30
	// days. Refresh tokens are rotated on every use; presenting an old
	// token after rotation revokes the family (RFC 9700 section 4.14).
	RefreshTokenTTL time.Duration

	// AuthorizationCodeTTL caps the lifetime of authorization codes.
	// Defaults to 60 seconds per OAuth 2.1 guidance.
	AuthorizationCodeTTL time.Duration

	// RegistrationAccessTokenTTL caps the lifetime of registration access
	// tokens minted on POST /oauth/register. Defaults to 365 days.
	RegistrationAccessTokenTTL time.Duration

	// AllowAnonymousRegistration permits POST /oauth/register without an
	// initial access token. Off by default. When on, the AS hard-pins
	// the endpoint to 1 request/min/IP and stamps the client row with
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

	// IntrospectionCacheTTL is the Cache-Control max-age the
	// introspection endpoint emits. Defaults to 60 seconds. Resource
	// servers may cache responses up to this duration.
	IntrospectionCacheTTL time.Duration

	// LoginURL is the path on this origin where unauthenticated
	// authorize requests are redirected. Defaults to "/auth/login". The
	// handler appends a `next` query parameter with the original
	// authorize URL.
	LoginURL string

	// DisableRotation skips the background JWKS rotation goroutine.
	// Tests use this to assert key state from a known fixture;
	// production must leave it false.
	DisableRotation bool
}

// ProtectedResource is defined in internal/models and re-exported from
// models_v20.go as a type alias. The struct definition was relocated as
// part of the arch-A0 models extraction so that every persistent and
// configuration entity lives in one package.

// validateASConfig applies defaults and screens required fields. PR B
// architecture reorg (2026-06-20): the validation body lives in
// internal/as.Validate; this stub mutates the supplied AS config in
// place (since internal/as.Validate operates on its own Config struct,
// we re-run validation by translating to the internal struct, calling
// Validate, then copying the defaults back).
func validateASConfig(cfg *AuthorizationServerConfig, encryptionKey []byte) error {
	if cfg == nil {
		return nil
	}
	internal := internalas.Config{
		Issuer:                         cfg.Issuer,
		SigningAlg:                     cfg.SigningAlg,
		KeyRotationPeriod:              cfg.KeyRotationPeriod,
		KeyRetention:                   cfg.KeyRetention,
		AccessTokenTTL:                 cfg.AccessTokenTTL,
		RefreshTokenTTL:                cfg.RefreshTokenTTL,
		AuthorizationCodeTTL:           cfg.AuthorizationCodeTTL,
		RegistrationAccessTokenTTL:     cfg.RegistrationAccessTokenTTL,
		AllowAnonymousRegistration:     cfg.AllowAnonymousRegistration,
		RegistrationRateLimitPerMinute: cfg.RegistrationRateLimitPerMinute,
		IntrospectionCacheTTL:          cfg.IntrospectionCacheTTL,
		LoginURL:                       cfg.LoginURL,
		DisableRotation:                cfg.DisableRotation,
	}
	if err := internalas.Validate(&internal, encryptionKey); err != nil {
		return err
	}
	// Mirror the populated defaults back so any downstream root code
	// that reads the original AuthorizationServerConfig pointer
	// (notably the public exported field at *TheAuth construction time)
	// sees the post-validation state.
	cfg.Issuer = internal.Issuer
	cfg.SigningAlg = internal.SigningAlg
	cfg.KeyRotationPeriod = internal.KeyRotationPeriod
	cfg.KeyRetention = internal.KeyRetention
	cfg.AccessTokenTTL = internal.AccessTokenTTL
	cfg.RefreshTokenTTL = internal.RefreshTokenTTL
	cfg.AuthorizationCodeTTL = internal.AuthorizationCodeTTL
	cfg.RegistrationAccessTokenTTL = internal.RegistrationAccessTokenTTL
	cfg.RegistrationRateLimitPerMinute = internal.RegistrationRateLimitPerMinute
	cfg.IntrospectionCacheTTL = internal.IntrospectionCacheTTL
	cfg.LoginURL = internal.LoginURL
	return nil
}

// invalidateClientAuthCache removed in PR G (2026-06-21). The previous
// unexported helper forwarded to a.as.InvalidateClientAuthCache. Every
// in-tree caller now invokes the internal/as Service method directly
// (rotation paths inside internal/as wire it themselves), so the root
// shim became dead. The internal entry point is still public for the
// extracted package.

// resourceByIdentifier removed in PR F when handlers_oauth_server.go
// moved into internal/as/handlers, which calls
// a.as.ResourceByIdentifier directly.
