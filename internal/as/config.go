package as

import (
	"errors"
	"strings"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/cimd"
	"github.com/glincker/theauth-go/internal/dpop"
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

	// Clock is the time source used by the introspection cache and the
	// chain-cache TTL. Defaults to a wrapper around time.Now when nil.
	// Tests pass a fake clock to assert revocation propagation
	// deterministically instead of sleeping past IntrospectionCacheTTL.
	Clock Clock

	// LoginURL is the path on this origin where unauthenticated authorize
	// requests are redirected. Defaults to "/auth/login".
	LoginURL string

	// DisableRotation skips the background JWKS rotation goroutine. Tests
	// use this to assert key state from a known fixture; production must
	// leave it false.
	DisableRotation bool

	// CIMD wires the Client ID Metadata Documents resolver, per MCP
	// authorization spec 2025-11-25. When non-nil, an incoming
	// /oauth/authorize or /oauth/token request whose client_id parses as
	// an https URL is resolved by fetching that URL and parsing the JSON
	// metadata document, instead of consulting OAuthServerStorage. Nil
	// disables CIMD entirely and the AS falls back to RFC 7591 DCR for
	// every client_id.
	CIMD *cimd.Config

	// DPoP, when non-nil, enables RFC 9449 sender-constrained access
	// tokens. When DPoP is set the token endpoint inspects every request
	// for a DPoP header, verifies the proof JWT, and embeds the RFC 7800
	// cnf.jkt confirmation claim in the issued access token. Resource
	// servers re-verify the same proof on every protected call. Leave
	// nil to disable DPoP entirely (pre-PR behavior; bearer tokens are
	// not sender constrained).
	DPoP *dpop.Config

	// RequireState, when true, causes StartAuthorize to reject any
	// /oauth/authorize request that omits a non-empty state parameter,
	// returning invalid_request. Default false preserves existing
	// behavior. Operators deploying browser-based clients should enable
	// this to enforce CSRF protection (security re-audit L5, 2026-06-22).
	RequireState bool

	// PAR wires RFC 9126 Pushed Authorization Requests. When non-nil and
	// the Storage backend implements PARStorage, POST /oauth/par is
	// enabled and GET /oauth/authorize accepts request_uri. Nil (default)
	// disables PAR entirely; existing deployments see no behavior change.
	PAR *PARConfig

	// JAR wires RFC 9101 JWT-Secured Authorization Requests. When
	// non-nil, /oauth/authorize and /oauth/par accept a "request"
	// parameter containing a signed JWT. Nil (default) disables JAR.
	JAR *JARConfig

	// JWTBearer, when non-nil, enables RFC 7523 client authentication and
	// the jwt-bearer grant. Mirrored from root JWTBearerConfig.
	JWTBearer *JWTBearerConfig

	// CIBA (RFC 9509) enables the backchannel authentication endpoints when
	// non-nil. When nil (default) the /oauth/bc-authorize endpoint is not
	// mounted and the AS metadata does not advertise CIBA fields.
	// Requires the Storage to also implement CIBAStorage; otherwise CIBA
	// is silently disabled even if this field is non-nil.
	CIBA *CIBAConfig
}

// JWTBearerConfig is the internal mirror of the root JWTBearerConfig.
// Populated once at New time; read-only afterwards.
type JWTBearerConfig struct {
	TrustedJWTIssuers     []TrustedJWTIssuer
	ClientAssertionMaxAge time.Duration
	AssertionMaxAge       time.Duration
	ReplayCacheTTL        time.Duration
	MaxActorChainDepth    int
}

// TrustedJWTIssuer is the internal mirror of the root TrustedJWTIssuer.
type TrustedJWTIssuer struct {
	Issuer            string
	JWKSURL           string
	AllowedAlgorithms []string
	// SubjectMapper resolves the "sub" (or other) claim to a local user ULID.
	// The internal package holds it as a plain func to avoid a dependency on
	// root interfaces.
	SubjectMapper func(claims map[string]any) (models.ULID, error)
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
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
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
	if cfg.PAR != nil {
		applyPARDefaults(cfg.PAR)
	}
	if cfg.JAR != nil {
		applyJARDefaults(cfg.JAR)
	}
	if cfg.JWTBearer != nil {
		if cfg.JWTBearer.ClientAssertionMaxAge <= 0 {
			cfg.JWTBearer.ClientAssertionMaxAge = 60 * time.Second
		}
		if cfg.JWTBearer.AssertionMaxAge <= 0 {
			cfg.JWTBearer.AssertionMaxAge = 300 * time.Second
		}
		if cfg.JWTBearer.ReplayCacheTTL <= 0 {
			cfg.JWTBearer.ReplayCacheTTL = 600 * time.Second
		}
		if cfg.JWTBearer.MaxActorChainDepth <= 0 {
			cfg.JWTBearer.MaxActorChainDepth = 5
		}
		for i, iss := range cfg.JWTBearer.TrustedJWTIssuers {
			if len(iss.AllowedAlgorithms) == 0 {
				cfg.JWTBearer.TrustedJWTIssuers[i].AllowedAlgorithms = []string{"ES256", "RS256", "EdDSA"}
			}
		}
	}
	// CIBA defaults.
	if cfg.CIBA != nil {
		if cfg.CIBA.AuthenticationDevice == nil {
			return errors.New("theauth: CIBAConfig.AuthenticationDevice is required when CIBA is enabled")
		}
		applyCIBADefaults(cfg.CIBA)
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
