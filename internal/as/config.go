package as

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/cimd"
	"github.com/glincker/theauth-go/v2/internal/dpop"
	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/pathprefix"
	"github.com/glincker/theauth-go/v2/kv"
)

// Config is the OAuth 2.1 and MCP authorization server configuration. It mirrors the root
// AuthorizationServerConfig and is read-only once the Service exists.
type Config struct {
	// Issuer is the canonical https URL that becomes the iss claim on every JWT. Trailing slashes are
	// stripped at validation.
	Issuer string

	// Resources lists the protected resources this AS advertises. Each authorize and token request
	// must carry a resource parameter matching one of them (RFC 8707, RFC 9068).
	Resources []models.ProtectedResource

	// SigningAlg is the default JWS algorithm for access tokens: EdDSA (default), ES256 or RS256.
	// Clients may select an alg listed in TokenPolicy.SigningAlgs.
	SigningAlg string

	// TokenPolicy enables per-client extra signing algorithms and opaque access tokens. Nil keeps
	// every client on EdDSA JWTs.
	TokenPolicy *TokenPolicyConfig

	// RAR enables RFC 9396 authorization_details when non-nil. Nil rejects the parameter.
	RAR *RARConfig

	// IDJAG enables Identity Assertion JWT Authorization Grants through token exchange, and their
	// redemption at jwt-bearer.
	IDJAG *IDJAGConfig

	// KeyRotationPeriod is how often the rotation goroutine promotes next, current and previous keys
	// (default 30 days).
	KeyRotationPeriod time.Duration

	// KeyRetention caps how long a retired key stays in /oauth/jwks (default 90 days).
	KeyRetention time.Duration

	// AccessTokenTTL caps access token lifetime (default 1 hour).
	AccessTokenTTL time.Duration

	// RefreshTokenTTL caps refresh token lifetime (default 30 days). Reuse of a rotated token revokes
	// the family (RFC 9700 section 4.14).
	RefreshTokenTTL time.Duration

	// AuthorizationCodeTTL caps authorization code lifetime (default 60 seconds, per OAuth 2.1).
	AuthorizationCodeTTL time.Duration

	// RegistrationAccessTokenTTL caps registration access tokens minted by POST /oauth/register
	// (default 365 days).
	RegistrationAccessTokenTTL time.Duration

	// AllowAnonymousRegistration permits POST /oauth/register without an initial access token. Off by default.
	AllowAnonymousRegistration bool

	// RegistrationTokens are the bearer initial access tokens accepted when DCR is bearer-gated. They
	// are hashed at New.
	RegistrationTokens []string

	// RegistrationRateLimitPerMinute caps POST /oauth/register per source IP.
	RegistrationRateLimitPerMinute int

	// IntrospectionCacheTTL is the Cache-Control max-age of introspection responses (default 60 seconds).
	IntrospectionCacheTTL time.Duration

	// SubjectActiveCacheTTL bounds reuse of a positive "subject still active" answer (agent status,
	// disabled flag) on the introspection hit path. Revocation drops entries at once. Zero means the
	// 1s default, negative disables, and values above 2s are clamped.
	SubjectActiveCacheTTL time.Duration

	// Clock is the time source for the caches. Defaults to time.Now. Tests inject a fake clock to
	// assert revocation deterministically.
	Clock Clock

	// ClockSkew is the tolerance for exp, nbf and iat checks on every JWT this AS verifies, and for
	// the DPoP proof iat window. Zero means no tolerance; negative values are treated as zero.
	ClockSkew time.Duration

	// OnTokenIssued mirrors the root hook. It runs before every access token is signed and returns the
	// claims to sign. An error aborts issuance. Keys that collide with registered claims (iss, sub,
	// aud, exp, iat, jti, client_id, scope, typ) are dropped at marshal time.
	OnTokenIssued func(ctx context.Context, claims map[string]any) (map[string]any, error)

	// ConsentHandler hands the consent decision to the host app after authentication and request
	// validation. It may approve (optionally narrowing scopes and setting an expiry), deny, or send
	// the user to the host's own consent page. Nil keeps auto-approve. See docs/oauth-consent.md.
	ConsentHandler ConsentHandler

	// ConsentMaxGrantTTL caps the lifetime of a grant approved through ConsentHandler. Zero means no
	// cap beyond token TTLs.
	ConsentMaxGrantTTL time.Duration

	// ConsentTicketTTL is how long a consent_ticket stays valid (default 10m).
	ConsentTicketTTL time.Duration

	// LoginURL is where unauthenticated authorize requests redirect (default "/auth/login").
	LoginURL string

	// DisableRotation skips the JWKS rotation goroutine. Tests use it to pin key state; production
	// must leave it false.
	DisableRotation bool

	// CIMD wires the Client ID Metadata Documents resolver. An https client_id is then
	// resolved by fetching its metadata document. Nil falls back to RFC 7591 DCR for every client_id.
	CIMD *cimd.Config

	// DPoP, when non-nil, enables RFC 9449 sender-constrained tokens: the token endpoint binds cnf.jkt
	// and resource servers re-verify the proof. Nil keeps plain Bearer tokens.
	DPoP *dpop.Config

	// RequireState makes StartAuthorize reject requests without a non-empty state (invalid_request).
	// Browser clients should enable it for CSRF protection (security re-audit L5).
	RequireState bool

	// AccessTokenRevocation turns on the store-backed access-token jti denylist. Revocation, code
	// replay and token-exchange checks consult it, and introspection reports revoked tokens inactive.
	// Off by default: local JWT verifiers never see it.
	AccessTokenRevocation bool

	// PAR wires RFC 9126 pushed authorization requests when non-nil and the Storage implements
	// PARStorage. Nil disables PAR.
	PAR *PARConfig

	// JAR wires RFC 9101 signed request objects on authorize and PAR. Nil disables JAR.
	JAR *JARConfig

	// JWTBearer, when non-nil, enables RFC 7523 client authentication and the jwt-bearer grant.
	JWTBearer *JWTBearerConfig

	// CIBA (RFC 9509) enables the backchannel endpoints when non-nil. It is silently disabled unless
	// the Storage implements CIBAStorage.
	CIBA *CIBAConfig

	// RateLimits tunes per-IP and per-client limits and the cap on concurrent client-secret
	// verifications. Nil applies the defaults.
	RateLimits *RateLimits

	// Stores supplies shared state backends (rate limiter, replay cache, caches). Nil fields use one
	// in-process memory store.
	Stores kv.Stores

	// DeviceAuthorization (RFC 8628) enables the device endpoint and grant when non-nil. Needs
	// DeviceAuthorizationStorage.
	DeviceAuthorization *DeviceConfig

	// RegistrationTokenTTL is the default lifetime of an initial access token created through the
	// admin API (default 24h).
	RegistrationTokenTTL time.Duration

	// DeviceTokens enables constrained device enrollment and the device assertion grant when non-nil.
	// Needs DeviceIdentityStorage.
	DeviceTokens *DeviceTokensConfig

	// OIDC turns the server into an OpenID Provider when non-nil: ID tokens, userinfo, end_session and
	// back-channel logout.
	OIDC *OIDCConfig

	// ClientCompat relaxes strictness checks for real-world clients. The zero value is fully strict.
	ClientCompat ClientCompat

	// ACRValues maps a sorted, "+"-joined amr method set (for example "pwd" or "otp+pwd") to the acr
	// string. Missing entries use ACRSingleFactor, or ACRMultiFactor for "mfa" or two or more methods.
	// A non-empty map is advertised as acr_values_supported.
	ACRValues map[string]string

	// SessionAMR reports a session's authentication methods. Nil assumes ["pwd"].
	SessionAMR func(ctx context.Context, sess *models.Session) []string
}

// JWTBearerConfig is the internal mirror of the root JWTBearerConfig, populated once at New.
type JWTBearerConfig struct {
	TrustedJWTIssuers     []TrustedJWTIssuer
	ClientAssertionMaxAge time.Duration
	AssertionMaxAge       time.Duration
	ReplayCacheTTL        time.Duration
	MaxActorChainDepth    int

	JWKSCacheTTL             time.Duration
	JWKSCacheMaxEntries      int
	JWKSFetchTimeout         time.Duration
	AllowPrivateJWKSNetworks bool
	JWKSHTTPClient           *http.Client
}

// TrustedJWTIssuer is the internal mirror of the root TrustedJWTIssuer.
type TrustedJWTIssuer struct {
	Issuer            string
	JWKSURL           string
	AllowedAlgorithms []string
	// SubjectMapper resolves the sub claim (or another claim) to a local user ULID. It is a plain func
	// so this package does not depend on root interfaces.
	SubjectMapper  func(claims map[string]any) (models.ULID, error)
	RequiredClaims []ClaimMatcher
	Audience       string
}

// Validate applies defaults and screens required fields. It mutates cfg in place so the Service
// keeps a fully populated config.
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
	if !jwt.SupportedAlg(cfg.SigningAlg) {
		return models.ErrASUnsupportedAlg
	}
	if err := validateTokenPolicy(cfg); err != nil {
		return err
	}
	if err := validateRAR(cfg.RAR); err != nil {
		return err
	}
	if cfg.CIMD != nil {
		if err := cfg.CIMD.Validate(); err != nil {
			return err
		}
	}
	if err := validateIDJAG(cfg); err != nil {
		return err
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
	switch {
	case cfg.SubjectActiveCacheTTL == 0:
		cfg.SubjectActiveCacheTTL = time.Second
	case cfg.SubjectActiveCacheTTL > maxSubjectActiveCacheTTL:
		cfg.SubjectActiveCacheTTL = maxSubjectActiveCacheTTL
	}
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	if cfg.ClockSkew < 0 {
		cfg.ClockSkew = 0
	}
	if cfg.LoginURL == "" {
		cfg.LoginURL = pathprefix.Default + "/login"
	}
	// Registration rate limit defaults: 1 request per minute per IP for the anonymous profile, 5 for
	// the bearer-gated one. A negative RegistrationRateLimitPerMinute disables the cap (security audit
	// H2).
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
		if cfg.JWTBearer.JWKSCacheTTL <= 0 {
			cfg.JWTBearer.JWKSCacheTTL = DefaultJWKSCacheTTL
		}
		if cfg.JWTBearer.JWKSCacheMaxEntries <= 0 {
			cfg.JWTBearer.JWKSCacheMaxEntries = DefaultJWKSCacheMaxEntries
		}
		if cfg.JWTBearer.JWKSFetchTimeout <= 0 {
			cfg.JWTBearer.JWKSFetchTimeout = DefaultJWKSFetchTimeout
		}
		if cfg.JWTBearer.MaxActorChainDepth <= 0 {
			cfg.JWTBearer.MaxActorChainDepth = 5
		}
		for i, iss := range cfg.JWTBearer.TrustedJWTIssuers {
			if err := validateClaimMatchers(iss.Issuer, iss.RequiredClaims); err != nil {
				return err
			}
			if len(iss.AllowedAlgorithms) == 0 {
				cfg.JWTBearer.TrustedJWTIssuers[i].AllowedAlgorithms = []string{"ES256", "RS256", "EdDSA"}
			}
		}
	}
	applyRateLimitDefaults(cfg)
	if cfg.RegistrationTokenTTL <= 0 {
		cfg.RegistrationTokenTTL = 24 * time.Hour
	}
	if cfg.DeviceAuthorization != nil {
		applyDeviceDefaults(cfg.DeviceAuthorization)
	}
	if cfg.DeviceTokens != nil {
		applyDeviceTokenDefaults(cfg.DeviceTokens)
	}
	if cfg.OIDC != nil {
		if err := validateOIDC(cfg.OIDC); err != nil {
			return err
		}
		applyOIDCDefaults(cfg.OIDC, cfg.AccessTokenTTL)
	}
	if cfg.CIBA != nil {
		if cfg.CIBA.AuthenticationDevice == nil {
			return errors.New("theauth: CIBAConfig.AuthenticationDevice is required when CIBA is enabled")
		}
		applyCIBADefaults(cfg.CIBA)
	}
	return nil
}

// AgentPolicy is the subset of the root AgentConfig the AS needs for delegation policy at token
// exchange: MaxChainDepth and the default TTL. It avoids a dependency on the root package.
type AgentPolicy struct {
	MaxChainDepth            int
	DefaultDelegatedTokenTTL time.Duration
}
