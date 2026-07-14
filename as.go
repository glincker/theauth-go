package theauth

import (
	"time"

	internalas "github.com/glincker/theauth-go/internal/as"
	internaldpop "github.com/glincker/theauth-go/internal/dpop"
)

// as.go: AuthorizationServerConfig declaration plus the thin forwarders
// that consolidate the small helpers historically attached to the *asState
// struct. PR B architecture reorg (2026-06-20) moved the runtime
// implementation to internal/as; the struct + asConfigFromRoot at the
// bottom of theauth.go preserve the wire shape and the New() defaults.

// Clock is the time source used by the introspection cache and the
// chain-cache TTL. Tests pass a fake clock to assert revocation
// propagation deterministically instead of sleeping past
// IntrospectionCacheTTL.
type Clock interface {
	Now() time.Time
}

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

	// Clock is the time source used by the introspection cache and the
	// chain-cache TTL. Defaults to a wrapper around time.Now when nil.
	// Tests pass a fake clock to assert revocation propagation
	// deterministically (e.g. introspecting immediately after revoke)
	// instead of sleeping past IntrospectionCacheTTL.
	Clock Clock

	// LoginURL is the path on this origin where unauthenticated
	// authorize requests are redirected. Defaults to "/auth/login". The
	// handler appends a `next` query parameter with the original
	// authorize URL.
	LoginURL string

	// DisableRotation skips the background JWKS rotation goroutine.
	// Tests use this to assert key state from a known fixture;
	// production must leave it false.
	DisableRotation bool

	// CIMD wires the Client ID Metadata Documents resolver per the MCP
	// authorization spec 2025-11-25. When non-nil, incoming
	// /oauth/authorize and /oauth/token requests whose client_id parses
	// as an https URL are resolved by fetching that URL and parsing the
	// JSON metadata document, instead of consulting OAuthServerStorage.
	// Nil disables CIMD and the AS falls back to RFC 7591 DCR for every
	// client_id (the pre-CIMD behavior).
	//
	// Default policy MUST be DenyAll (fail-closed); operators opt in to
	// AllowAnyHTTPS or AllowHTTPSHosts explicitly.
	CIMD *CIMDConfig

	// DPoP, when non-nil, enables RFC 9449 sender-constrained access
	// tokens. The token endpoint inspects each request for a DPoP
	// header, verifies the proof JWT, and embeds an RFC 7800 cnf.jkt
	// confirmation claim in the issued access token. Resource servers
	// (mcpresource) re-verify the same proof on every protected call,
	// so a stolen access token cannot be replayed without the private
	// key that signed the proof. Leave nil for pre-PR behavior
	// (Bearer tokens, no sender constraint).
	DPoP *DPoPConfig

	// RequireState, when true, causes the /oauth/authorize endpoint to
	// reject any request that omits a non-empty state parameter, returning
	// invalid_request. Default false preserves existing behavior for
	// backwards compatibility. Operators deploying browser-based clients
	// should set this to true to enforce CSRF protection for every
	// authorization request (security re-audit L5, 2026-06-22).
	RequireState bool

	// PAR wires RFC 9126 Pushed Authorization Requests. When non-nil and
	// the Storage backend implements PARStorage, POST /oauth/par is
	// registered and GET /oauth/authorize accepts request_uri. Nil (the
	// default) disables PAR; existing deployments see no behavior change.
	PAR *PARConfig

	// JAR wires RFC 9101 JWT-Secured Authorization Requests. When
	// non-nil, /oauth/authorize and /oauth/par accept a "request"
	// parameter containing a signed JWT. Nil (the default) disables JAR.
	JAR *JARConfig

	// JWTBearer, when non-nil, enables two RFC 7523 features:
	//
	// (1) private_key_jwt / client_secret_jwt client authentication on the
	//     token endpoint (RFC 7523 section 2.2). Clients registered with
	//     token_endpoint_auth_method = "private_key_jwt" or
	//     "client_secret_jwt" authenticate by presenting a signed JWT as
	//     client_assertion instead of a client_secret.
	//
	// (2) The urn:ietf:params:oauth:grant-type:jwt-bearer grant type (RFC
	//     7523 section 2.1). A JWT issued by a configured trusted external
	//     issuer (e.g. Google, k8s OIDC, AWS IAM Roles Anywhere) is
	//     exchanged for an AS-issued access token.
	//
	// When nil both features are disabled and the AS behaves as before
	// (client_secret_basic / client_secret_post only).
	JWTBearer *JWTBearerConfig

	// CIBA enables Client-Initiated Backchannel Authentication (RFC 9509)
	// when non-nil. The storage backend must also implement CIBAStorage;
	// if it does not, CIBA endpoints are not mounted regardless of this
	// setting. Default nil disables CIBA.
	CIBA *CIBAConfig
}

// JWTBearerConfig controls RFC 7523 JWT client authentication and the
// JWT Bearer grant type. All fields have safe defaults.
type JWTBearerConfig struct {
	// TrustedJWTIssuers is the list of external issuers whose JWTs may be
	// exchanged for AS-issued access tokens via the jwt-bearer grant (RFC
	// 7523 section 2.1). Each entry must specify Issuer and JWKSURL;
	// AllowedAlgorithms defaults to ["ES256","RS256","EdDSA"].
	TrustedJWTIssuers []TrustedJWTIssuer

	// ClientAssertionMaxAge bounds how far in the past the client assertion
	// JWT's iat claim may be. Defaults to 60 seconds (RFC 7523 recommends
	// short-lived assertions). Operators may tighten but rarely need to
	// widen this.
	ClientAssertionMaxAge time.Duration

	// AssertionMaxAge bounds how far in the past the bearer grant assertion
	// JWT's iat claim may be. Defaults to 300 seconds.
	AssertionMaxAge time.Duration

	// ReplayCacheTTL is the duration JTIs remain in the replay cache.
	// Defaults to 600 seconds (covers the maximum assertion lifetime with
	// comfortable margin). Backed by JWTBearerStorage.InsertJTI; backends
	// that do not implement JWTBearerStorage fall back to an in-process
	// sync.Map and lose replay protection across restarts.
	ReplayCacheTTL time.Duration

	// MaxActorChainDepth caps on-behalf-of actor chains in the RFC 8693
	// token-exchange grant. Defaults to 5. Values above 10 are not
	// recommended: each additional link adds a storage round-trip at
	// token-exchange time.
	MaxActorChainDepth int
}

// TrustedJWTIssuer is one entry in JWTBearerConfig.TrustedJWTIssuers.
type TrustedJWTIssuer struct {
	// Issuer is the value the trusted issuer places in the iss claim of
	// its JWTs. Must be an exact string match.
	Issuer string

	// JWKSURL is the URL of the issuer's JSON Web Key Set document.
	// Fetched and cached by the AS; rotated on 401 or periodic refresh.
	JWKSURL string

	// AllowedAlgorithms is the set of JWS algorithms the AS will accept
	// for this issuer. Defaults to ES256, RS256, EdDSA.
	AllowedAlgorithms []string

	// SubjectMapper resolves the "sub" claim (and any other claims) of
	// the external JWT to a local user ULID. When nil the built-in
	// SubMapper is used: the sub claim is parsed directly as a ULID.
	// Use EmailMapper to resolve the email claim to a local user.Email
	// row instead.
	SubjectMapper SubjectMapper
}

// SubjectMapper resolves claims from a trusted external JWT to a local
// user ULID. Two built-in implementations are provided:
//
//   - SubMapper: treats the "sub" claim as a ULID directly.
//   - EmailMapper: looks up the user by the "email" claim value.
//
// Custom implementations may consult any claim in the map; the AS passes
// the full decoded payload.
type SubjectMapper interface {
	// Resolve returns the local user ULID for the supplied claim map, or
	// ErrStorageNotFound when no mapping exists. Any other error is
	// treated as a transient failure and returned as server_error.
	Resolve(claims map[string]any) (ULID, error)
}

// SubMapper is the built-in SubjectMapper that parses the "sub" claim
// directly as a ULID. Use when the external issuer's subject is the
// theauth user ID (e.g. for internal workload tokens).
type SubMapper struct{}

// Resolve implements SubjectMapper by parsing claims["sub"] as a ULID.
func (SubMapper) Resolve(claims map[string]any) (ULID, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return ULID{}, ErrStorageNotFound
	}
	var id ULID
	if err := id.UnmarshalText([]byte(sub)); err != nil {
		return ULID{}, ErrStorageNotFound
	}
	return id, nil
}

// EmailMapper is the built-in SubjectMapper that looks up the user by
// email. The Lookup function must be provided (the AS wires in
// Storage.UserByEmail). Returns ErrStorageNotFound when no user with
// that email exists.
type EmailMapper struct {
	// Lookup finds a user by their email address. Wire in
	// Storage.UserByEmail at startup.
	Lookup func(email string) (ULID, error)
}

// Resolve implements SubjectMapper by resolving claims["email"] to a user ID.
func (m EmailMapper) Resolve(claims map[string]any) (ULID, error) {
	email, _ := claims["email"].(string)
	if email == "" {
		return ULID{}, ErrStorageNotFound
	}
	if m.Lookup == nil {
		return ULID{}, ErrStorageNotFound
	}
	return m.Lookup(email)
}

// PARConfig is the root-package alias for as.PARConfig. Consumers set
// Config.AuthorizationServer.PAR to enable RFC 9126 support.
type PARConfig = internalas.PARConfig

// JARConfig is the root-package alias for as.JARConfig. Consumers set
// Config.AuthorizationServer.JAR to enable RFC 9101 support.
type JARConfig = internalas.JARConfig

// DPoPConfig configures the RFC 9449 DPoP verifier wired into both the
// authorization server and the mcpresource validator. All fields are
// optional; New populates sensible defaults when the operator does not
// override them. The wire shape matches the internal dpop.Config 1:1
// because every field is operator-visible policy.
type DPoPConfig struct {
	// RequireDPoPForClients lists OAuth client IDs that MUST present a
	// DPoP proof on every token request. Clients not on this list may
	// still opt in by sending DPoP voluntarily; if they do, the issued
	// token is sender constrained. For clients on this list, the
	// absence of a proof is a 400 invalid_dpop_proof.
	RequireDPoPForClients []string

	// AllowedSignAlgs is the whitelist of signing algorithms a proof
	// JWT may use. Defaults to ES256, ES384, RS256, PS256, EdDSA. HMAC
	// algorithms (HS*) and "none" are always rejected per RFC 9449
	// section 4.2.
	AllowedSignAlgs []string

	// ProofMaxAge bounds how far in the past or future the proof's iat
	// claim may be. Defaults to 60 seconds; values much above 5 minutes
	// substantially weaken the protection.
	ProofMaxAge time.Duration

	// NonceTTL bounds how long an issued DPoP-Nonce remains acceptable.
	// Defaults to 10 minutes. Increasing this widens the window during
	// which a captured nonce remains replayable; decreasing it forces
	// clients to handle the use_dpop_nonce retry path more often.
	NonceTTL time.Duration

	// RequireNonceForTokens forces the token endpoint to demand a nonce
	// on every DPoP proof. A first-call proof without a nonce returns
	// HTTP 400 use_dpop_nonce + a DPoP-Nonce response header for the
	// retry. Off by default; turn this on when running an AS exposed to
	// untrusted clients to bound proof replay.
	RequireNonceForTokens bool

	// NonceSecret is the HMAC-SHA256 secret used to mint + verify
	// DPoP-Nonce headers. Leave empty to let New generate a fresh
	// 32-byte secret at startup; supply a stable value here when
	// running multiple AS instances behind a load balancer so any
	// instance can verify a nonce issued by any other.
	NonceSecret []byte

	// JTIReplayWindow caps the in-memory jti LRU size used to reject
	// replayed proofs within ProofMaxAge. Defaults to 4096; raise for
	// high-throughput AS deployments and lower for memory-constrained
	// ones. A value of 0 means default.
	JTIReplayWindow int
}

// dpopConfigFromRoot translates the root DPoPConfig into the internal
// dpop.Config the verifier consumes. Nil-safe; returns nil so the AS
// service short-circuits DPoP handling.
func dpopConfigFromRoot(c *DPoPConfig) *internaldpop.Config {
	if c == nil {
		return nil
	}
	return &internaldpop.Config{
		RequireDPoPForClients: append([]string(nil), c.RequireDPoPForClients...),
		AllowedSignAlgs:       append([]string(nil), c.AllowedSignAlgs...),
		ProofMaxAge:           c.ProofMaxAge,
		NonceTTL:              c.NonceTTL,
		RequireNonceForTokens: c.RequireNonceForTokens,
		NonceSecret:           append([]byte(nil), c.NonceSecret...),
		JTIReplayWindow:       c.JTIReplayWindow,
	}
}

// jwtBearerConfigFromRoot translates the root JWTBearerConfig into the
// internal/as JWTBearerConfig. Nil-safe; returns nil to disable JWT bearer.
func jwtBearerConfigFromRoot(c *JWTBearerConfig) *internalas.JWTBearerConfig {
	if c == nil {
		return nil
	}
	issuers := make([]internalas.TrustedJWTIssuer, len(c.TrustedJWTIssuers))
	for i, t := range c.TrustedJWTIssuers {
		algs := append([]string(nil), t.AllowedAlgorithms...)
		var mapper func(map[string]any) (ULID, error)
		if t.SubjectMapper != nil {
			sm := t.SubjectMapper
			mapper = sm.Resolve
		}
		issuers[i] = internalas.TrustedJWTIssuer{
			Issuer:            t.Issuer,
			JWKSURL:           t.JWKSURL,
			AllowedAlgorithms: algs,
			SubjectMapper:     mapper,
		}
	}
	return &internalas.JWTBearerConfig{
		TrustedJWTIssuers:     issuers,
		ClientAssertionMaxAge: c.ClientAssertionMaxAge,
		AssertionMaxAge:       c.AssertionMaxAge,
		ReplayCacheTTL:        c.ReplayCacheTTL,
		MaxActorChainDepth:    c.MaxActorChainDepth,
	}
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
		Clock:                          cfg.Clock,
		LoginURL:                       cfg.LoginURL,
		DisableRotation:                cfg.DisableRotation,
		DPoP:                           dpopConfigFromRoot(cfg.DPoP),
		RequireState:                   cfg.RequireState,
		PAR:                            cfg.PAR,
		JAR:                            cfg.JAR,
		JWTBearer:                      jwtBearerConfigFromRoot(cfg.JWTBearer),
		CIBA:                           cibaConfigToInternal(cfg.CIBA),
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
	cfg.Clock = internal.Clock
	cfg.LoginURL = internal.LoginURL
	// Mirror CIBA defaults back.
	if cfg.CIBA != nil && internal.CIBA != nil {
		cfg.CIBA.DefaultExpiry = internal.CIBA.DefaultExpiry
		cfg.CIBA.DefaultInterval = internal.CIBA.DefaultInterval
		cfg.CIBA.MaxRequestedExpiry = internal.CIBA.MaxRequestedExpiry
		cfg.CIBA.MinPollInterval = internal.CIBA.MinPollInterval
	}
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
