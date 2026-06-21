package as

import (
	"strings"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/models"
)

// Config wires the OAuth 2.1 + MCP authorization server runtime. Mirror of
// the root AuthorizationServerConfig; ferried in by *theauth.TheAuth.New
// once at startup, then read-only for the life of the Service.
type Config struct {
	// Issuer is the canonical https URL identifying this authorization
	// server. Becomes the iss claim on every issued JWT. RFC 8414 mandates
	// no query or fragment; trailing slash is stripped at validation.
	Issuer string

	// Resources lists the protected resources advertised by this AS. Every
	// authorize and token request MUST carry a resource parameter that
	// matches one of these identifiers; the resulting JWT's aud claim is
	// set from the resource (RFC 8707 + RFC 9068).
	Resources []models.ProtectedResource

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
	// initial access token. Off by default.
	AllowAnonymousRegistration bool

	// RegistrationTokens is the operator-supplied set of bearer initial
	// access tokens that POST /oauth/register accepts when DCR is bearer
	// gated. Pre-hashed at New time; the plaintext is dropped.
	RegistrationTokens []string

	// RegistrationRateLimitPerMinute caps POST /oauth/register at this
	// many requests per source IP per minute.
	RegistrationRateLimitPerMinute int

	// IntrospectionCacheTTL is the Cache-Control max-age the introspection
	// endpoint emits. Defaults to 60 seconds.
	IntrospectionCacheTTL time.Duration

	// LoginURL is the path on this origin where unauthenticated authorize
	// requests are redirected. Defaults to "/auth/login".
	LoginURL string

	// DisableRotation skips the background JWKS rotation goroutine. Tests
	// use this to assert key state from a known fixture; production must
	// leave it false.
	DisableRotation bool
}

// Validate applies defaults and screens required fields. Mirror of the
// root validateASConfig; mutates cfg in place so the on-disk Service ends
// up with a fully populated config.
func Validate(cfg *Config, encryptionKey []byte) error {
	if cfg == nil {
		return nil
	}
	if cfg.Issuer == "" {
		return models.ErrASIssuerRequired
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if len(encryptionKey) != crypto.AESKeyLen {
		return models.ErrASRequiresEncryptionKey
	}
	if cfg.SigningAlg == "" {
		cfg.SigningAlg = "EdDSA"
	}
	if cfg.SigningAlg != "EdDSA" {
		return models.ErrASUnsupportedAlg
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
	// enforced. Defaults: 1 req/min/IP for the anonymous public-MCP
	// profile, 5 req/min/IP for the bearer-gated profile. Operators that
	// need different limits set RegistrationRateLimitPerMinute explicitly;
	// a negative value disables the cap.
	if cfg.RegistrationRateLimitPerMinute == 0 {
		if cfg.AllowAnonymousRegistration {
			cfg.RegistrationRateLimitPerMinute = 1
		} else {
			cfg.RegistrationRateLimitPerMinute = 5
		}
	}
	return nil
}

// AgentPolicy is the subset of root *AgentConfig that the AS needs to
// enforce delegation policy at token-exchange time. Held on the Service
// so the token-exchange path can read MaxChainDepth and the default TTL
// without taking a dependency on the root package.
type AgentPolicy struct {
	MaxChainDepth            int
	DefaultDelegatedTokenTTL time.Duration
}
