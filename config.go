package theauth

import (
	"context"
	"net/http"
	"time"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/bootstrap"
	internaldpop "github.com/glincker/theauth-go/v2/internal/dpop"
	internaloauth "github.com/glincker/theauth-go/v2/internal/oauth"
	"github.com/glincker/theauth-go/v2/internal/password"
	"github.com/glincker/theauth-go/v2/internal/rbac"
	"github.com/glincker/theauth-go/v2/internal/throttle"
)

// config.go holds the concrete sub-config types that hang off Config.
// Moved from theauth.go into config.go in PR H (2026-06-22) to bring
// theauth.go below the 500 LOC ceiling. The types are unchanged; this is
// a pure file split with no API impact.

// AgentConfig wires the agent-identity policy. Set on Config.AgentIdentity
// to enable Phase 3 + 4 behavior (agents + delegations + token-exchange).
// The zero value AgentConfig{} is valid and is interpreted as accept-all-
// defaults at New.
type AgentConfig struct {
	// MaxChainDepth caps the actor chain length. Defaults to 3 (root subject
	// plus two agents). Operators may lower (to 2, disabling sub-delegation)
	// but never raise above 3 in v2.0; New returns an error if asked to.
	MaxChainDepth int

	// MaxDelegationDuration caps any single delegation_grants.max_duration.
	// Defaults to 90 days. Per-grant max_duration_seconds MUST be <= this.
	MaxDelegationDuration time.Duration

	// DefaultDelegatedTokenTTL is the default exp window for tokens minted
	// via the token-exchange grant when the requester does not narrow it
	// further. Defaults to 15 minutes.
	DefaultDelegatedTokenTTL time.Duration

	// AgentSecretLength controls bytes of entropy in generated agent
	// secrets. Defaults to 32 (256 bits). Stored hashed (Argon2id);
	// transmitted exactly once at creation or rotation.
	AgentSecretLength int
}

// RBACConfig configures organization-scoped roles and permissions. The zero
// value is valid and accepts the seeded permission list plus the seeded
// "owner", "admin", "member" roles.
type RBACConfig struct {
	// Permissions extends the seeded catalog. Names are deduped by case-
	// sensitive equality with the seeded list. New returns an error if any
	// supplied name contains whitespace or non-ASCII (permission names are
	// program identifiers, not user input).
	Permissions []Permission

	// DefaultRoles seeds every new organization. When empty the three
	// default roles ("owner", "admin", "member") are used. Reserved names
	// ("owner", "admin", "member") must remain present when consumers
	// override; New returns an error otherwise.
	DefaultRoles []RoleSeed
}

// RoleSeed describes one organization-scoped role created at
// SeedOrganizationRoles time. Permissions are permission names; unknown
// names cause New to return a validation error so typos surface at startup
// instead of on the first permission check.
type RoleSeed = rbac.RoleSeed

// AuditConfig configures the async audit writer. All fields have safe
// defaults; the zero value AuditConfig{} is valid.
type AuditConfig struct {
	// BufferSize is the channel buffer between EmitAudit and the writer
	// goroutine. Defaults to 4096. When full, EmitAudit drops the event
	// and increments Stats.AuditDropped.
	BufferSize int

	// BatchSize is the maximum events per INSERT. Defaults to 100.
	BatchSize int

	// FlushInterval is the maximum delay before a partial batch flushes.
	// Defaults to 1 second.
	FlushInterval time.Duration

	// Redactor optionally transforms metadata before storage. The default
	// redactor strips the keys "password", "secret", "token", "code",
	// "refresh_token", "access_token" (case-insensitive) at any nesting
	// depth and replaces their values with the string "[REDACTED]".
	Redactor func(metadata map[string]any) map[string]any

	// DrainTimeout caps how long Close waits for the writer goroutine to
	// drain remaining events. Defaults to 5 seconds.
	DrainTimeout time.Duration

	// Sinks is the optional list of external SIEM streaming destinations.
	// After each successful canonical storage write the writer goroutine
	// fans out to every sink in a separate goroutine. A failing sink is
	// logged at Warn level, counted in Stats.AuditSinkFailed, and
	// silently dropped: sink failures NEVER block storage writes or delay
	// the next batch. Built-in implementations are in sub-packages of
	// audit/sinks/.
	Sinks []AuditSink
}

// AdminConfig mounts /admin/v1/* when non-nil on the same chi router passed
// to Mount.
type AdminConfig struct {
	// PathPrefix where admin routes mount. Defaults to "/admin/v1".
	PathPrefix string
}

// OrganizationsConfig is currently empty: there are no tunables for v0.7.
// The presence of a non-nil value is the signal that multi-tenancy is on.
// Future fields (default member role, invitation TTL, etc.) land here without
// breaking the existing zero-value wiring.
type OrganizationsConfig struct{}

// SAMLConfig wires the Service Provider keypair and base behavior. Per-IdP
// configuration lives in saml_connections rows, not here.
type SAMLConfig struct {
	// SPCertificatePEM and SPPrivateKeyPEM are PEM-encoded; they sign every
	// outbound AuthnRequest and identify the SP in metadata XML. New returns
	// an error if either is missing or unparseable.
	SPCertificatePEM []byte
	SPPrivateKeyPEM  []byte

	// AuthnRequestTTL caps how long an outstanding SP-initiated AuthnRequest
	// ID is tracked for replay protection. Defaults to 10 minutes.
	AuthnRequestTTL time.Duration

	// ClockSkew accepted on Conditions.NotBefore / NotOnOrAfter. Defaults to
	// 30 seconds (matches crewjam default). Some IdPs (Okta on slow clocks)
	// need 60s.
	ClockSkew time.Duration

	// AllowedRelayStates lists extra post-login destinations accepted as
	// RelayState (exact absolute URLs, or "/" prefixes ending in "*").
	// Same-site paths and Config.PostLoginRedirect are always accepted;
	// any other RelayState falls back to PostLoginRedirect.
	AllowedRelayStates []string
}

// SCIMConfig wires the SCIM 2.0 endpoint behavior.
type SCIMConfig struct {
	// RequireHTTPS rejects requests whose r.TLS is nil and whose
	// X-Forwarded-Proto header is not "https". Default true. Set false only
	// when SCIM is fronted by a TLS-terminating proxy that strips the header
	// (in which case the proxy is responsible for TLS).
	RequireHTTPS bool

	// MaxPageSize caps the count parameter on list endpoints. Defaults to
	// 200. RFC 7644 section 3.4.2 lets the server enforce a maximum.
	MaxPageSize int
}

// WebAuthnConfig wires the Relying Party identity. Field names mirror the
// upstream go-webauthn/webauthn.Config so consumers reading either set of
// docs see the same vocabulary.
type WebAuthnConfig struct {
	// RPID is the Relying Party Server ID. e.g. "glinr.com" (eTLD+1 of the
	// origin, no scheme, no port). Required.
	RPID string
	// RPDisplayName is shown by browsers and authenticators. Required.
	RPDisplayName string
	// RPOrigins is the fully qualified origins permitted to invoke the
	// API, e.g. ["https://glinr.com"]. At least one required.
	RPOrigins []string
	// ChallengeTTL caps how long the in-memory challenge session is valid.
	// Defaults to 5 minutes; challenges are single-use regardless.
	ChallengeTTL time.Duration
	// RequireUserVerification makes registration and login demand user
	// verification (PIN or biometric), so a passkey is never a bare
	// possession factor. Defaults to false (v2 behavior: UV "preferred").
	RequireUserVerification bool
	// CloneWarning selects what happens when an assertion's sign count
	// fails to advance, the signal of a cloned authenticator. The default,
	// CloneWarningReject, refuses the login; CloneWarningFlag lets it
	// through and emits a passkey.clone_warning audit event.
	CloneWarning CloneWarningPolicy
}

// CloneWarningPolicy selects the response to a sign count regression.
type CloneWarningPolicy string

const (
	// CloneWarningReject refuses a login whose sign count did not advance.
	CloneWarningReject CloneWarningPolicy = "reject"
	// CloneWarningFlag allows the login and records an audit event.
	CloneWarningFlag CloneWarningPolicy = "flag"
)

// LifecycleHooks lets consumers react to authentication-lifecycle events
// without forking handlers or wrapping every endpoint at the HTTP boundary.
// All fields are optional; nil hooks are silent no-ops. Hooks run
// synchronously on the request goroutine after the underlying operation
// succeeds and before the HTTP response is written.
//
// A non-nil error returned from a hook is logged at Warn level via slog and
// does NOT fail the request: the request that triggered the hook has already
// succeeded, and rolling back is not possible without coordinated storage
// transactions. Use hooks for fire-and-observe behavior (provisioning,
// analytics, notifications). For request-failing side effects, wrap at the
// handler boundary.
//
// Panics in hooks are recovered and logged via slog; the request continues
// as if the hook had returned nil.
//
// OnTokenIssued is the only hook permitted to mutate state: it receives the
// claims map about to be signed into a JWT access token and returns the
// updated map. Returning a non-nil error from OnTokenIssued does fail token
// issuance because the token has not yet been minted.
//
// Wiring status (v2.5): every hook below is wired. OnSignup fires from
// password, magic-link, OAuth callback, SAML, and a user's first-ever
// WebAuthn credential (passkey registration has no true account-creation
// moment, so the first credential is the closest equivalent). OnSignin
// fires from password, magic-link, and OAuth callback. OnTokenIssued
// fires from every OAuth access-token grant. OnOrgSwitch fires only from
// the explicit SetActiveOrganization call, not from auto-provisioned
// personal orgs.
// OAuthConflictPayload is passed to LifecycleHooks.OnOAuthConflict when a
// sign-in OAuth email matches an existing user who registered via a different
// provider. The consumer creates a verification challenge and returns the URL
// the browser should be redirected to.
type OAuthConflictPayload struct {
	Provider        string
	ProviderUserID  string
	ProviderEmail   string
	ProviderName    string
	ProviderAvatar  string
	ExistingUserID  string // ULID string of the existing user
	AccessTokenEnc  []byte // AES-GCM encrypted provider access token
	RefreshTokenEnc []byte // AES-GCM encrypted provider refresh token (may be nil)
	ExpiresAt       *time.Time
	Scope           string
}

type LifecycleHooks struct {
	OnSignup         func(ctx context.Context, user *User, method SignupMethod) error
	OnSignin         func(ctx context.Context, user *User, sess *Session) error
	OnPasswordChange func(ctx context.Context, user *User) error
	OnMFAEnabled     func(ctx context.Context, user *User, kind MFAKind) error
	OnTokenIssued    func(ctx context.Context, claims map[string]any) (map[string]any, error)
	OnOrgSwitch      func(ctx context.Context, user *User, orgID string) error
	// OnOAuthConflict fires when a sign-in OAuth email matches an existing user
	// registered via a different provider. The hook must create a short-lived
	// verification challenge and return the redirect URL for it. When nil the
	// sign-in proceeds normally (silent provider linking).
	OnOAuthConflict func(ctx context.Context, p OAuthConflictPayload) (redirectURL string, err error)
}

// TenancyConfig (v2.5) wires opt-in tenant-provisioning behavior so
// consumers do not need to seed organization_members + roles + active-org
// SQL on every fresh signup. Only takes effect when Config.Organizations
// is also non-nil; otherwise auto-provisioning silently no-ops.
type TenancyConfig struct {
	// AutoCreatePersonalOrg controls whether a personal organization is
	// created automatically on every signup that goes through the wired
	// hook paths (password, magic-link, OAuth callback). The user is
	// added as the organization owner and the session's active
	// organization is set to it. When false (default) the library does
	// not touch organizations at signup; consumers wire their own
	// provisioning logic via LifecycleHooks.OnSignup.
	AutoCreatePersonalOrg bool

	// PersonalOrgNameFn produces the human-readable organization name.
	// Default: the user's email address.
	PersonalOrgNameFn func(*User) string

	// PersonalOrgSlugFn produces the URL-safe slug. Default: the lowercased
	// ULID of the user prefixed with "personal-" (e.g. "personal-01h...");
	// guarantees uniqueness without requiring a slug-conflict retry loop.
	PersonalOrgSlugFn func(*User) string
}

// TOTPConfig wires the second-factor TOTP behavior. Algorithm is fixed at
// SHA-1 / 30s / 6 digits for compatibility with Google Authenticator, Authy,
// 1Password, and every other mainstream authenticator app. Skew is fixed at
// one period before/after (the pquerna/otp default) to absorb client clock
// drift.
type TOTPConfig struct {
	// Issuer is shown in the authenticator app, e.g. "GLINR Quarter".
	Issuer string
	// RecoveryCodeCount defaults to 10 when zero. Each code is 10 hex chars
	// (40 bits of entropy) generated via crypto/rand.
	RecoveryCodeCount int
}

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

// OAuthState is the per-flow record kept between /start and /callback.
type OAuthState = internaloauth.State

// OAuthStateStore holds OAuth flow state between /start and /callback.
// Implement it over a shared store (Redis, SQL) to run several replicas
// behind a load balancer; the default in-memory store is single-process.
type OAuthStateStore = internaloauth.StateStore

// NewMemoryOAuthStateStore returns the default in-process OAuthStateStore.
// It sweeps expired entries in the background; call Close when done.
func NewMemoryOAuthStateStore() *internaloauth.MemoryStateStore {
	return internaloauth.NewMemoryStateStore()
}

// OAuthSignupPolicy decides whether an OAuth sign-in may create a new user.
type OAuthSignupPolicy string

const (
	// OAuthSignupOpen lets any provider-authenticated identity create an
	// account. It is the default so existing v2 deployments are unchanged.
	OAuthSignupOpen OAuthSignupPolicy = "open"
	// OAuthSignupClosed refuses to create users from OAuth; only existing
	// users and linked accounts can sign in.
	OAuthSignupClosed OAuthSignupPolicy = "closed"
	// OAuthSignupAllowedDomains creates users only when the provider-verified
	// email domain is listed in OAuthConfig.AllowedEmailDomains.
	OAuthSignupAllowedDomains OAuthSignupPolicy = "allowed_domains"
	// OAuthSignupInvite creates users only when OAuthConfig.InviteCheck
	// approves the verified email.
	OAuthSignupInvite OAuthSignupPolicy = "invite"
)

// OAuthConfig tunes OAuth login hardening. The zero value keeps v2
// behavior: in-memory state with a 10 minute TTL, no return-to parameter,
// and open signup.
type OAuthConfig struct {
	// StateStore overrides the default in-memory state store.
	StateStore OAuthStateStore
	// StateTTL bounds how long a flow may take. Defaults to 10 minutes.
	StateTTL time.Duration
	// AllowedReturnTo lists the post-login destinations a caller may request
	// with ?return_to=. Entries are exact absolute URLs or paths beginning
	// with "/" (matched as exact path, or prefix when ending in "*").
	// Anything else is ignored and Config.PostLoginRedirect is used.
	AllowedReturnTo []string
	// Signup selects the new-user policy. Defaults to OAuthSignupOpen.
	Signup OAuthSignupPolicy
	// AllowedEmailDomains is required for OAuthSignupAllowedDomains.
	AllowedEmailDomains []string
	// InviteCheck is required for OAuthSignupInvite. It receives the
	// provider-verified, lower-cased email.
	InviteCheck func(ctx context.Context, email string) (bool, error)
	// RedirectURI, when set, builds the redirect_uri sent to the provider
	// instead of BaseURL + prefix + "/providers/{name}/callback". Use it to
	// keep callback URLs already registered at the provider. r is the
	// request that began the flow. The value is stored with the state and
	// reused verbatim at code exchange. It must be an absolute https URL
	// (http only for loopback or with AllowInsecureRedirectURI) with no
	// fragment or userinfo; any error fails the start. Deriving the host
	// from an unvalidated Host or X-Forwarded-Host header is unsafe: set
	// RedirectURIAllowedHosts. Experimental.
	RedirectURI func(r *http.Request, provider string) (string, error)
	// RedirectURIAllowedHosts, when non-empty, restricts the host (or
	// host:port) RedirectURI may return; anything else fails closed.
	// Experimental.
	RedirectURIAllowedHosts []string
	// AllowInsecureRedirectURI permits an http:// RedirectURI result on a
	// non-loopback host. For development only. Experimental.
	AllowInsecureRedirectURI bool
}

func oauthConfigFromRoot(c *OAuthConfig, prefix string) internaloauth.Config {
	if c == nil {
		return internaloauth.Config{PathPrefix: prefix}
	}
	return internaloauth.Config{
		PathPrefix:          prefix,
		StateStore:          c.StateStore,
		StateTTL:            c.StateTTL,
		AllowedReturnTo:     append([]string(nil), c.AllowedReturnTo...),
		Signup:              string(c.Signup),
		AllowedEmailDomains: append([]string(nil), c.AllowedEmailDomains...),
		InviteCheck:         c.InviteCheck,

		RedirectURI:              c.RedirectURI,
		RedirectURIAllowedHosts:  append([]string(nil), c.RedirectURIAllowedHosts...),
		AllowInsecureRedirectURI: c.AllowInsecureRedirectURI,
	}
}

// LoginThrottleStore persists login and MFA throttle counters. The default
// is an in-memory store; supply your own to share state across processes.
type LoginThrottleStore = throttle.Store

// LoginThrottleEntry is one record held by a LoginThrottleStore.
type LoginThrottleEntry = throttle.Entry

// LoginThrottleCASStore is the optional LoginThrottleStore capability that
// lets several processes share counters without losing updates.
type LoginThrottleCASStore = throttle.CASStore

// BreachChecker reports whether a password appears in a known breach corpus.
type BreachChecker = password.BreachChecker

// HIBPBreachChecker is a BreachChecker backed by the Have I Been Pwned
// k-anonymity range API.
type HIBPBreachChecker = password.HIBPChecker

// NewMemoryLoginThrottleStore returns the default in-memory store, capped at
// maxEntries (zero selects 100000). Expired entries are swept on writes.
func NewMemoryLoginThrottleStore(maxEntries int) LoginThrottleStore {
	return throttle.NewMemoryStore(maxEntries)
}

// LoginThrottleConfig tunes login backoff, per-user lockout and MFA attempt
// limits. The nil Config.LoginThrottle selects the defaults below; set
// Disabled to turn the feature off.
type LoginThrottleConfig struct {
	Disabled bool
	// Store defaults to an in-memory store.
	Store LoginThrottleStore
	// GraceFailures is how many failed logins per (IP, identifier) pass
	// before backoff starts. Default 3.
	GraceFailures int
	// BaseDelay is the first backoff delay, doubled per further failure. Default 1s.
	BaseDelay time.Duration
	// MaxDelay caps the backoff. Default 15m.
	MaxDelay time.Duration
	// ResetAfter forgets failure counts after this much idle time. Default 15m.
	ResetAfter time.Duration
	// UserMaxFailures consecutive failures against one identifier, from any
	// IP, trigger a lockout. Default 10.
	UserMaxFailures int
	// UserLockout is how long that lockout lasts before auto-expiring. Default 15m.
	UserLockout time.Duration
	// MFAMaxFailures wrong TOTP or recovery codes per user, across all
	// pending sessions, trigger an MFA lockout. Default 5.
	MFAMaxFailures int
	// MFALockout is how long the MFA lockout lasts. Default 15m.
	MFALockout time.Duration
	// MaxEntries caps the default in-memory store. Default 100000.
	MaxEntries int
}

func (c *LoginThrottleConfig) limiter() *throttle.Limiter {
	if c == nil {
		return throttle.New(nil, throttle.Config{})
	}
	if c.Disabled {
		return nil
	}
	store := c.Store
	if store == nil {
		store = throttle.NewMemoryStore(c.MaxEntries)
	}
	return throttle.New(store, throttle.Config{
		GraceFailures:   c.GraceFailures,
		BaseDelay:       c.BaseDelay,
		MaxDelay:        c.MaxDelay,
		ResetAfter:      c.ResetAfter,
		UserMaxFailures: c.UserMaxFailures,
		UserLockout:     c.UserLockout,
		MFAMaxFailures:  c.MFAMaxFailures,
		MFALockout:      c.MFALockout,
	})
}

// BootstrapConfig closes public signup and gates creation of the first user
// behind a one-time setup token. The storage must implement UserCountStorage.
//
// While no user exists, password signup requires the token in the
// X-Setup-Token header or a "setupToken" body field. After the first user
// exists, signup is refused with CodeSignupClosed unless
// OpenSignupAfterFirstUser is set. Magic-link account creation follows the
// same rule but can never present a token, so the first admin must sign up
// with a password. Granting the new user an admin role is left to OnFirstUser.
type BootstrapConfig = bootstrap.Config
