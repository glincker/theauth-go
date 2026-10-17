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

// AgentConfig wires the agent-identity policy. Set it on Config.AgentIdentity to enable agents,
// delegations and token exchange. The zero value is valid and means accept-all defaults at New.
type AgentConfig struct {
	// MaxChainDepth caps the actor chain length (default 3: root subject plus two agents). Operators may
	// lower it to 2 to disable sub-delegation, but New rejects values above 3 in v2.0.
	MaxChainDepth int

	// MaxDelegationDuration caps any single delegation_grants.max_duration.
	// Defaults to 90 days. Per-grant max_duration_seconds MUST be <= this.
	MaxDelegationDuration time.Duration

	// DefaultDelegatedTokenTTL is the exp window for token-exchange tokens when the requester does not
	// narrow it (default 15 minutes).
	DefaultDelegatedTokenTTL time.Duration

	// AgentSecretLength is the entropy in bytes of generated agent secrets (default 32, 256 bits). Secrets
	// are stored hashed (Argon2id) and shown once, at creation or rotation.
	AgentSecretLength int

	// PolicyEngine, when set, evaluates the agent's IAM policies on every agent token mint. An explicit Deny
	// fails the mint with access_denied, scopes no Allow covers are narrowed away, and the policy ids and
	// hash go into the agent_policy claim and audit event. Build one with the agentpolicy package.
	PolicyEngine AgentPolicyEngine

	// RateLimit bounds how often each agent (keyed by agent id) may mint tokens or call AuthorizeAgent.
	// Over the limit the mint gets HTTP 429 with Retry-After. The zero value disables it.
	RateLimit AgentRateLimit
}

// RBACConfig configures organization-scoped roles and permissions. The zero
// value is valid and accepts the seeded permission list plus the seeded
// "owner", "admin", "member" roles.
type RBACConfig struct {
	// Permissions extends the seeded catalog, deduped by case-sensitive name. New rejects names containing
	// whitespace or non-ASCII, since permission names are program identifiers.
	Permissions []Permission

	// DefaultRoles seeds every new organization; empty uses owner, admin and member. Reserved names must
	// stay present when overridden, or New returns an error.
	DefaultRoles []RoleSeed
}

// RoleSeed describes one organization-scoped role created at SeedOrganizationRoles time. Unknown
// permission names make New fail so typos surface at startup.
type RoleSeed = rbac.RoleSeed

// AuditConfig configures the async audit writer. The zero value is valid.
type AuditConfig struct {
	// BufferSize is the channel buffer between EmitAudit and the writer goroutine (default 4096). When full,
	// EmitAudit drops the event and increments Stats.AuditDropped.
	BufferSize int

	// BatchSize is the maximum events per INSERT. Defaults to 100.
	BatchSize int

	// FlushInterval is the maximum delay before a partial batch flushes (default 1 second).
	FlushInterval time.Duration

	// Redactor optionally transforms metadata before storage. The default strips password, secret,
	// token, code, refresh_token and access_token keys (case-insensitive) at any depth, replacing
	// values with "[REDACTED]".
	Redactor func(metadata map[string]any) map[string]any

	// DrainTimeout caps how long Close waits for the writer goroutine to drain (default 5 seconds).
	DrainTimeout time.Duration

	// Sinks are optional SIEM streaming destinations, fanned out after each successful storage write. A
	// failing sink is logged at Warn, counted in Stats.AuditSinkFailed and dropped, so sink failures never
	// block storage writes. Built-in sinks live in audit/sinks/.
	Sinks []AuditSink

	// FailClosed makes decision-class audit events fail closed: when one cannot be queued, EmitDecision
	// returns an error so the caller can deny the action. Off by default so audit pressure never blocks
	// request paths.
	FailClosed bool

	// DecisionActionPrefixes overrides the audit action prefixes treated as decision-class for FailClosed.
	DecisionActionPrefixes []string
}

// AdminConfig mounts /admin/v1/* on the router passed to Mount when non-nil.
type AdminConfig struct {
	// PathPrefix where admin routes mount. Defaults to "/admin/v1".
	PathPrefix string
}

// OrganizationsConfig is empty for now; a non-nil value turns multi-tenancy on. Future tunables land
// here without breaking zero-value wiring.
type OrganizationsConfig struct{}

// SAMLConfig wires the Service Provider keypair and base behavior. Per-IdP
// configuration lives in saml_connections rows, not here.
type SAMLConfig struct {
	// SPCertificatePEM and SPPrivateKeyPEM sign every outbound AuthnRequest; New fails if either is unparseable.
	SPCertificatePEM []byte
	SPPrivateKeyPEM  []byte

	// AuthnRequestTTL caps how long an SP-initiated AuthnRequest ID is tracked for replay protection
	// (default 10 minutes).
	AuthnRequestTTL time.Duration

	// ClockSkew tolerated on Conditions.NotBefore and NotOnOrAfter (default 30 seconds; some IdPs need 60).
	ClockSkew time.Duration

	// AllowedRelayStates lists extra post-login destinations accepted as RelayState (exact URLs or "/" prefixes
	// ending in "*"); any other value falls back to PostLoginRedirect.
	AllowedRelayStates []string
}

// SCIMConfig wires the SCIM 2.0 endpoint behavior.
type SCIMConfig struct {
	// RequireHTTPS rejects requests without TLS whose X-Forwarded-Proto is not "https" (default true). Set false
	// only behind a TLS-terminating proxy that strips the header.
	RequireHTTPS bool

	// MaxPageSize caps the count parameter on list endpoints (default 200; RFC 7644 section 3.4.2).
	MaxPageSize int
}

// WebAuthnConfig wires the Relying Party identity. Field names mirror go-webauthn/webauthn.Config.
type WebAuthnConfig struct {
	// RPID is the Relying Party ID, the eTLD+1 of the origin (for example "glinr.com"). Required.
	RPID string
	// RPDisplayName is shown by browsers and authenticators. Required.
	RPDisplayName string
	// RPOrigins lists the origins allowed to call the WebAuthn API, for example ["https://glinr.com"].
	RPOrigins []string
	// ChallengeTTL caps how long a challenge is valid (default 5 minutes; challenges are single-use).
	ChallengeTTL time.Duration
	// RequireUserVerification makes registration and login demand PIN or biometric verification, so a passkey
	// is never a bare possession factor. Default false (UV "preferred").
	RequireUserVerification bool
	// CloneWarning picks what happens when an assertion's sign count fails to advance (a cloned authenticator).
	// The default rejects the login; CloneWarningFlag allows it and emits passkey.clone_warning.
	CloneWarning CloneWarningPolicy
	// UserHandleResolver lets passkeys imported from another system sign in when their user handle is not a
	// theauth handle. It must return the user the handle denotes; login is refused unless that matches the
	// credential's stored owner. Nil accepts only theauth handles.
	UserHandleResolver func(ctx context.Context, credentialID, userHandle []byte) (ULID, error)

	// AttestationPreference is the attestation conveyance requested: "none" (default), "indirect", "direct" or
	// "enterprise". Trust anchors (FIDO MDS) are not configured here.
	AttestationPreference string

	// RequireAttestationStatement rejects registrations with attestation format "none"; pair with "direct".
	RequireAttestationStatement bool

	// AAGUIDAllowlist, when non-empty, accepts only these authenticator models (UUID strings).
	AAGUIDAllowlist []string

	// AAGUIDDenylist rejects these authenticator models and wins over the allowlist.
	AAGUIDDenylist []string

	// AuthenticatorNames maps an AAGUID to a display name for UIs.
	AuthenticatorNames map[string]string

	// AuthenticatorName is an optional lookup consulted before
	// AuthenticatorNames, receiving a lowercase hyphenated AAGUID.
	AuthenticatorName func(aaguid string) string
}

// CloneWarningPolicy selects the response to a sign count regression.
type CloneWarningPolicy string

const (
	// CloneWarningReject refuses a login whose sign count did not advance.
	CloneWarningReject CloneWarningPolicy = "reject"
	// CloneWarningFlag allows the login and records an audit event.
	CloneWarningFlag CloneWarningPolicy = "flag"
)

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

// LifecycleHooks lets consumers react to authentication lifecycle events without forking handlers.
// All fields are optional and run after the underlying operation succeeds, before the response is
// written. OnSignup, OnSignin, OnPasswordChange, OnMFAEnabled and OnOrgSwitch are observe-only:
// errors and panics are logged (and reported to OnHookError) but never fail the request. Gate a
// signup at the route instead. OnTokenIssued is the only hook that may mutate state: it returns the
// claims to sign, and an error fails issuance.
type LifecycleHooks struct {
	OnSignup         func(ctx context.Context, user *User, method SignupMethod) error
	OnSignin         func(ctx context.Context, user *User, sess *Session) error
	OnPasswordChange func(ctx context.Context, user *User) error
	OnMFAEnabled     func(ctx context.Context, user *User, kind MFAKind) error
	OnTokenIssued    func(ctx context.Context, claims map[string]any) (map[string]any, error)
	OnOrgSwitch      func(ctx context.Context, user *User, orgID string) error
	// OnAccountDeleted runs after the delete committed; user is the snapshot taken just before it. It is
	// observe-only, so errors and panics are only logged.
	OnAccountDeleted func(ctx context.Context, user *User) error
	// OnOAuthConflict fires when a sign-in email matches a user registered via another provider. It must return
	// a redirect URL for a short-lived verification challenge; nil silently links the providers.
	OnOAuthConflict func(ctx context.Context, p OAuthConflictPayload) (redirectURL string, err error)

	// OnHookError, when set, receives the hook name and error whenever an observe-only hook fails or panics. It
	// runs in addition to the slog line, must stay fast, and cannot change request outcomes.
	OnHookError func(ctx context.Context, hook string, err error)
}

// TenancyConfig (v2.5) opts into tenant provisioning so consumers need not seed organization rows on signup.
// It takes effect only when Config.Organizations is set.
type TenancyConfig struct {
	// AutoCreatePersonalOrg creates a personal organization (user as owner, set active) on every wired signup
	// path. Default false; wire custom provisioning via LifecycleHooks.OnSignup instead.
	AutoCreatePersonalOrg bool

	// PersonalOrgNameFn returns the display name of a personal organization (default: the user's email).
	PersonalOrgNameFn func(*User) string

	// PersonalOrgSlugFn returns a URL-safe slug (default "personal-" plus the lowercased ULID, unique without a
	// conflict-retry loop).
	PersonalOrgSlugFn func(*User) string
}

// TOTPConfig wires second-factor TOTP. Algorithm is fixed at SHA-1, 30s and 6 digits for compatibility with
// mainstream authenticator apps; skew is one period either side.
type TOTPConfig struct {
	// Issuer is shown in the authenticator app, e.g. "GLINR Quarter".
	Issuer string
	// RecoveryCodeCount is the number of recovery codes (default 10); each carries 40 bits from crypto/rand.
	RecoveryCodeCount int
}

// Clock is the time source for the introspection cache and chain-cache TTL. Tests inject a fake clock to
// assert revocation deterministically.
type Clock interface {
	Now() time.Time
}

// AuthorizationServerConfig wires the OAuth 2.1 and MCP authorization server. Set it on
// Config.AuthorizationServer to mount /.well-known/ and /oauth/ routes; nil keeps v1.0 behavior.
type AuthorizationServerConfig struct {
	// Issuer is the canonical https URL that becomes the iss claim on every JWT (no query or fragment).
	Issuer string

	// Resources lists the protected resources this AS advertises. Every authorize and token request must carry
	// a resource parameter matching one of them (RFC 8707, RFC 9068).
	Resources []ProtectedResource

	// SigningAlg defaults to EdDSA (Ed25519). Phase 1 + 2 ships Ed25519
	// only.
	SigningAlg string

	// KeyRotationPeriod is how often the JWKS rotation goroutine promotes keys (default 30 days).
	KeyRotationPeriod time.Duration

	// KeyRetention caps how long a retired key stays in /oauth/jwks (default 90 days).
	KeyRetention time.Duration

	// AccessTokenTTL caps the lifetime of access tokens (default 1 hour).
	AccessTokenTTL time.Duration

	// RefreshTokenTTL caps refresh token lifetime (default 30 days). Refresh tokens rotate on use; reuse of an
	// old one revokes the family (RFC 9700 section 4.14).
	RefreshTokenTTL time.Duration

	// AuthorizationCodeTTL caps authorization code lifetime (default 60 seconds, per OAuth 2.1).
	AuthorizationCodeTTL time.Duration

	// RegistrationAccessTokenTTL caps registration access tokens minted by POST /oauth/register
	// (default 365 days).
	RegistrationAccessTokenTTL time.Duration

	// AllowAnonymousRegistration permits POST /oauth/register without an initial access token. Off by
	// default; when on, the endpoint is pinned to 1 request per minute per IP and clients are stamped
	// AnonymousRegistered.
	AllowAnonymousRegistration bool

	// RegistrationTokens is the operator-supplied set of bearer initial access tokens accepted by POST
	// /oauth/register while DCR is bearer-gated (the default). Tokens are SHA-256 hashed at New and compared in
	// constant time. With no tokens and AllowAnonymousRegistration false, every registration gets 401
	// (security audit H1).
	RegistrationTokens []string

	// RegistrationRateLimitPerMinute caps POST /oauth/register per source IP. Defaults to 1 with
	// AllowAnonymousRegistration and 5 otherwise; negative disables the cap, which is not advised on a
	// public bind (security audit H2).
	RegistrationRateLimitPerMinute int

	// IntrospectionCacheTTL is the Cache-Control max-age emitted by the introspection endpoint
	// (default 60 seconds).
	IntrospectionCacheTTL time.Duration

	// SubjectActiveCacheTTL bounds how long a positive subject-active lookup (agent status, user disabled state)
	// is reused during introspection. Revocation events drop the entry at once; default 1 second, capped at 2,
	// negative disables.
	SubjectActiveCacheTTL time.Duration

	// Clock overrides the time source; see the Clock type.
	Clock Clock

	// LoginURL is where unauthenticated authorize requests redirect, with a next parameter (default
	// "/auth/login").
	LoginURL string

	// DisableRotation skips the background JWKS rotation goroutine. Tests use it to pin key state;
	// production must leave it false.
	DisableRotation bool

	// CIMD wires Client ID Metadata Documents. When non-nil, client_ids that parse as https URLs are
	// resolved by fetching their metadata instead of consulting storage. Nil falls back to RFC 7591
	// DCR. The default policy is DenyAll; operators opt in to AllowAnyHTTPS or AllowHTTPSHosts.
	CIMD *CIMDConfig

	// DPoP, when non-nil, enables RFC 9449 sender-constrained tokens: the token endpoint binds cnf.jkt
	// and resource servers re-verify the proof on every call, so a stolen token cannot be replayed
	// without the proof key.
	DPoP *DPoPConfig

	// RequireState makes /oauth/authorize reject requests without a non-empty state parameter
	// (invalid_request). Default false for compatibility; browser clients should enable it for CSRF
	// protection (security re-audit L5).
	RequireState bool

	// AccessTokenRevocation enables the store-backed access-token jti denylist (opt-in). Revocation,
	// code replay and token exchange honor it, and introspection reports revoked tokens inactive.
	// Local JWT verifiers never consult it and must introspect. Default false keeps access tokens
	// stateless.
	AccessTokenRevocation bool

	// ClientCompat relaxes strictness checks so real-world MCP clients (Claude Desktop, Cursor,
	// ChatGPT) interoperate. Every switch defaults to strict; LoopbackAnyPort and DropUnknownScopes
	// carry real tradeoffs (see docs/client-compat.md).
	ClientCompat ClientCompatConfig

	// ACRValues maps a sorted, "+"-joined amr method set (for example "pwd" or "otp+pwd") to the acr
	// claim (RFC 9470 step-up). Missing entries use urn:theauth:acr:1fa for one method and
	// urn:theauth:acr:mfa otherwise.
	ACRValues map[string]string

	// SessionAMR overrides the RFC 8176 methods used for the amr and acr claims. By default it is
	// Session.AuthMethods (sessions with no record assume ["pwd"]). A non-empty result wins; called on
	// /oauth/authorize only.
	SessionAMR func(ctx context.Context, sess *Session) []string

	// PAR wires RFC 9126 pushed authorization requests. When non-nil and the storage implements PARStorage,
	// POST /oauth/par is mounted and authorize accepts request_uri. Nil disables PAR.
	PAR *PARConfig

	// JAR wires RFC 9101 signed request objects on /oauth/authorize and /oauth/par. Nil disables JAR.
	JAR *JARConfig

	// JWTBearer enables RFC 7523 features: private_key_jwt and client_secret_jwt client authentication
	// at the token endpoint (section 2.2), and the jwt-bearer grant that exchanges JWTs from trusted
	// external issuers (section 2.1). Nil disables both.
	JWTBearer *JWTBearerConfig

	// CIBA enables RFC 9509 backchannel authentication when non-nil. Endpoints mount only if storage
	// implements CIBAStorage.
	CIBA *CIBAConfig

	// DeviceAuthorization enables the RFC 8628 device grant when non-nil. Storage must implement
	// DeviceAuthorizationStorage (memory, SQLite, Postgres and MySQL do); clients opt in by
	// registering the device_code grant.
	DeviceAuthorization *DeviceAuthorizationConfig

	// TokenPolicy enables per-client extra signing algorithms (ES256, RS256) and opaque reference
	// tokens. Nil keeps every client on EdDSA JWTs. Opaque tokens need OpaqueTokenStorage.
	TokenPolicy *TokenPolicyConfig

	// RAR enables RFC 9396 authorization_details on authorize, PAR, JAR and the token endpoint. Nil
	// rejects the parameter.
	RAR *RARConfig

	// IDJAG enables Identity Assertion JWT Authorization Grants through token exchange and their
	// redemption at the jwt-bearer grant (which also needs JWTBearer). Nil disables both.
	IDJAG *IDJAGConfig

	// RateLimits tunes the per-IP and per-client limits on the AS endpoints and the cap on concurrent Argon2id
	// client-secret verifications. Nil applies the defaults; set a field negative to turn it off.
	RateLimits *ASRateLimits

	// RegistrationTokenTTL is the default lifetime of an initial access token (default 24h).
	RegistrationTokenTTL time.Duration

	// DeviceTokens enables constrained device identity when non-nil: join tokens, enrollment at
	// /oauth/devices/enroll, and the jwt-bearer grant for registered devices (short-lived tokens, no
	// refresh). Storage must implement DeviceIdentityStorage.
	DeviceTokens *DeviceTokensConfig

	// OIDC turns the server into an OpenID Provider when non-nil. See docs/oidc-provider.md.
	OIDC *OIDCConfig

	// ConsentHandler hands the consent decision to the host app, after authentication and request
	// validation. It returns Approve (optionally with narrowed scopes and a grant expiry), Deny, or
	// Interact (render the host's consent page, then resume with TheAuth.CompleteConsent). Nil keeps
	// auto-approve. See docs/oauth-consent.md.
	ConsentHandler ConsentHandler

	// ConsentMaxGrantTTL caps the lifetime of a grant approved through ConsentHandler. Zero means no extra cap.
	ConsentMaxGrantTTL time.Duration

	// ConsentTicketTTL is the validity of a consent_ticket (default 10m).
	ConsentTicketTTL time.Duration
}

// ConsentHandler, ConsentRequest, ConsentDecision and friends are the root aliases for the
// host-owned consent API.
type (
	ConsentHandler  = internalas.ConsentHandler
	ConsentRequest  = internalas.ConsentRequest
	ConsentDecision = internalas.ConsentDecision
	ConsentClient   = internalas.ConsentClient
	ConsentAction   = internalas.ConsentAction
)

const (
	ConsentApprove          = internalas.ConsentApprove
	ConsentDeny             = internalas.ConsentDeny
	ConsentInteract         = internalas.ConsentInteract
	ConsentSourceRegistered = internalas.ConsentSourceRegistered
	ConsentSourceCIMD       = internalas.ConsentSourceCIMD
)

var (
	ErrConsentTicketInvalid   = internalas.ErrConsentTicketInvalid
	ErrConsentDecisionInvalid = internalas.ErrConsentDecisionInvalid
)

// OIDCConfig is the root alias for the OpenID Provider settings.
type OIDCConfig = internalas.OIDCConfig

// TokenPolicyConfig is the root alias for the per-client token policy.
type TokenPolicyConfig = internalas.TokenPolicyConfig

// RARConfig is the root alias for the RFC 9396 settings.
type RARConfig = internalas.RARConfig

// IDJAGConfig is the root alias for the ID-JAG settings.
type IDJAGConfig = internalas.IDJAGConfig

// DeviceAuthorizationConfig is the root alias for the RFC 8628 settings.
type DeviceAuthorizationConfig = internalas.DeviceConfig

// DeviceTokensConfig is the root alias for the device identity settings.
type DeviceTokensConfig = internalas.DeviceTokensConfig

// DevicePage is the view model handed to DeviceAuthorizationConfig.Page.
type DevicePage = internalas.DevicePage

// ASRateLimits is the root alias for the AS endpoint limits.
type ASRateLimits = internalas.RateLimits

// CreateDeviceJoinTokenInput describes a device join token to mint.
type CreateDeviceJoinTokenInput = internalas.CreateDeviceJoinTokenInput

// CreateRegistrationTokenInput describes an initial access token to mint.
type CreateRegistrationTokenInput = internalas.CreateRegistrationTokenInput

// JWTBearerConfig controls RFC 7523 client authentication and the JWT Bearer grant. All fields have
// safe defaults.
type JWTBearerConfig struct {
	// TrustedJWTIssuers lists external issuers whose JWTs may be exchanged for AS tokens (RFC 7523 section 2.1).
	// Each entry needs Issuer and JWKSURL; AllowedAlgorithms defaults to ES256, RS256 and EdDSA.
	TrustedJWTIssuers []TrustedJWTIssuer

	// ClientAssertionMaxAge bounds how far in the past a client assertion's iat may be (default 60 seconds).
	ClientAssertionMaxAge time.Duration

	// AssertionMaxAge bounds how far in the past a bearer grant assertion's iat may be (default 300 seconds).
	AssertionMaxAge time.Duration

	// ReplayCacheTTL is how long JTIs stay in the replay cache (default 600 seconds, covering the
	// maximum assertion lifetime). Backends without JWTBearerStorage fall back to an in-process map
	// and lose replay protection on restart.
	ReplayCacheTTL time.Duration

	// MaxActorChainDepth caps on-behalf-of actor chains in the RFC 8693 token-exchange grant (default 5).
	MaxActorChainDepth int

	// JWKSCacheTTL is how long a fetched JWKS is reused, so key rotation is picked up (default 5
	// minutes). Failed fetches are never cached.
	JWKSCacheTTL time.Duration

	// JWKSCacheMaxEntries bounds how many distinct JWKS URLs are cached (default 256).
	JWKSCacheMaxEntries int

	// JWKSFetchTimeout is the total time allowed for one JWKS fetch (default 5 seconds).
	JWKSFetchTimeout time.Duration

	// AllowPrivateJWKSNetworks disables the dial-time block on loopback, private, link-local and
	// metadata addresses, and permits plain http JWKS URLs. Development only: it re-opens SSRF to
	// internal hosts.
	AllowPrivateJWKSNetworks bool

	// JWKSHTTPClient, when non-nil, replaces the SSRF-guarded client used for JWKS fetches. It is used
	// as-is, so it must provide the same protection (no redirects, address guard). Intended for tests.
	JWKSHTTPClient *http.Client
}

// TrustedJWTIssuer is one entry in JWTBearerConfig.TrustedJWTIssuers.
type TrustedJWTIssuer struct {
	// Issuer is the exact iss value this trusted issuer places in its JWTs.
	Issuer string

	// JWKSURL is the URL of the issuer's JSON Web Key Set, fetched and cached by the AS.
	JWKSURL string

	// AllowedAlgorithms is the set of JWS algorithms accepted for this issuer (default ES256, RS256, EdDSA).
	AllowedAlgorithms []string

	// SubjectMapper resolves the external JWT's claims to a local user ULID. When nil the built-in
	// SubMapper is used. Use EmailMapper to resolve the email claim to a local user instead.
	SubjectMapper SubjectMapper

	// RequiredClaims are matchers every verified assertion from this issuer must satisfy before it is
	// exchanged. A missing claim fails closed and matching is case sensitive. With none configured
	// every validly signed assertion is accepted, which is unsafe for multi-tenant issuers such as
	// GitHub Actions: see GitHubActionsIssuer.
	RequiredClaims []ClaimMatcher

	// Audience, when non-empty, is the aud value assertions from this issuer must carry instead of the
	// AS issuer URL.
	Audience string
}

// ClaimMatcher requires one claim of a verified jwt-bearer assertion to satisfy exactly one operator (Equals,
// OneOf, Pattern or Present).
type ClaimMatcher = internalas.ClaimMatcher

// ErrInvalidClaimMatcher is returned by New (wrapped) for a misconfigured ClaimMatcher.
var ErrInvalidClaimMatcher = internalas.ErrInvalidClaimMatcher

// SubjectMapper resolves claims from a trusted external JWT to a local user ULID. The built-ins are
// SubMapper (the sub claim is a ULID) and EmailMapper (the email claim names a user). Custom
// implementations see the full payload.
type SubjectMapper interface {
	// Resolve returns the local user ULID for the claims, or ErrStorageNotFound when no mapping
	// exists. Other errors are treated as transient and returned as server_error.
	Resolve(claims map[string]any) (ULID, error)
}

// SubMapper is the built-in SubjectMapper that parses the "sub" claim as a ULID (for example for
// internal workload tokens).
type SubMapper struct{}

// Resolve returns the local user ULID for the supplied claim map, or ErrStorageNotFound when no
// mapping exists.
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

// EmailMapper is the built-in SubjectMapper that looks up the user by email. Lookup must be set; the AS wires
// Storage.UserByEmail. Returns ErrStorageNotFound when no such user exists.
type EmailMapper struct {
	// Lookup finds a user by email address. Wire in Storage.UserByEmail at startup.
	Lookup func(email string) (ULID, error)
}

// Resolve returns the local user ULID for the supplied claim map, or ErrStorageNotFound when no
// mapping exists.
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

// ClientCompatConfig is the root alias for as.ClientCompat. The zero value is fully strict.
type ClientCompatConfig = internalas.ClientCompat

// PARConfig is the root alias for as.PARConfig. Set Config.AuthorizationServer.PAR to enable RFC 9126.
type PARConfig = internalas.PARConfig

// JARConfig is the root alias for as.JARConfig. Set Config.AuthorizationServer.JAR to enable RFC 9101.
type JARConfig = internalas.JARConfig

// DPoPConfig configures the RFC 9449 DPoP verifier shared by the authorization server and
// mcpresource. Fields are optional and defaulted by New; the shape matches the internal
// dpop.Config.
type DPoPConfig struct {
	// RequireDPoPForClients lists client IDs that must present a DPoP proof on every token request
	// (400 otherwise).
	RequireDPoPForClients []string

	// AllowedSignAlgs whitelists proof signing algorithms (default ES256, ES384, RS256, PS256, EdDSA).
	// HMAC and "none" are always rejected per RFC 9449 section 4.2.
	AllowedSignAlgs []string

	// ProofMaxAge bounds how far from now a proof's iat may be (default 60 seconds; much above 5
	// minutes weakens protection).
	ProofMaxAge time.Duration

	// NonceTTL bounds how long an issued DPoP-Nonce stays acceptable (default 10 minutes).
	NonceTTL time.Duration

	// RequireNonceForTokens makes the token endpoint demand a nonce on every proof (400 use_dpop_nonce
	// on the first call). Off by default; enable it for an AS exposed to untrusted clients to bound
	// proof replay.
	RequireNonceForTokens bool

	// NonceSecret is the HMAC-SHA256 key that mints and verifies DPoP-Nonce values. Empty generates a
	// random key at startup; set a stable value when several AS instances sit behind a load balancer.
	NonceSecret []byte

	// JTIReplayWindow caps the in-memory jti LRU used to reject replayed proofs within ProofMaxAge
	// (default 4096; 0 means default).
	JTIReplayWindow int
}

// dpopConfigFromRoot translates the root DPoPConfig into the internal dpop.Config. Nil-safe.
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

// jwtBearerConfigFromRoot translates the root JWTBearerConfig into the internal one. Nil-safe.
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
			RequiredClaims:    append([]ClaimMatcher(nil), t.RequiredClaims...),
			Audience:          t.Audience,
		}
	}
	return &internalas.JWTBearerConfig{
		TrustedJWTIssuers:     issuers,
		ClientAssertionMaxAge: c.ClientAssertionMaxAge,
		AssertionMaxAge:       c.AssertionMaxAge,
		ReplayCacheTTL:        c.ReplayCacheTTL,
		MaxActorChainDepth:    c.MaxActorChainDepth,

		JWKSCacheTTL:             c.JWKSCacheTTL,
		JWKSCacheMaxEntries:      c.JWKSCacheMaxEntries,
		JWKSFetchTimeout:         c.JWKSFetchTimeout,
		AllowPrivateJWKSNetworks: c.AllowPrivateJWKSNetworks,
		JWKSHTTPClient:           c.JWKSHTTPClient,
	}
}

// validateASConfig applies defaults and screens required fields. The validation body lives in
// internal/as.Validate; this copies the defaults back onto cfg so root code sees the
// post-validation state.
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
		SubjectActiveCacheTTL:          cfg.SubjectActiveCacheTTL,
		Clock:                          cfg.Clock,
		LoginURL:                       cfg.LoginURL,
		DisableRotation:                cfg.DisableRotation,
		DPoP:                           dpopConfigFromRoot(cfg.DPoP),
		RequireState:                   cfg.RequireState,
		AccessTokenRevocation:          cfg.AccessTokenRevocation,
		ClientCompat:                   cfg.ClientCompat,
		CIMD:                           cfg.CIMD,
		PAR:                            cfg.PAR,
		JAR:                            cfg.JAR,
		JWTBearer:                      jwtBearerConfigFromRoot(cfg.JWTBearer),
		CIBA:                           cibaConfigToInternal(cfg.CIBA),
		DeviceAuthorization:            cfg.DeviceAuthorization,
		TokenPolicy:                    cfg.TokenPolicy,
		RAR:                            cfg.RAR,
		IDJAG:                          cfg.IDJAG,
		RateLimits:                     cfg.RateLimits,
		RegistrationTokenTTL:           cfg.RegistrationTokenTTL,
		DeviceTokens:                   cfg.DeviceTokens,
		OIDC:                           cfg.OIDC,
		ConsentHandler:                 cfg.ConsentHandler,
		ConsentMaxGrantTTL:             cfg.ConsentMaxGrantTTL,
		ConsentTicketTTL:               cfg.ConsentTicketTTL,
	}
	if err := internalas.Validate(&internal, encryptionKey); err != nil {
		return err
	}
	// Mirror the populated defaults back so root code reading the AuthorizationServerConfig sees
	// post-validation state.
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
	cfg.SubjectActiveCacheTTL = internal.SubjectActiveCacheTTL
	cfg.Clock = internal.Clock
	cfg.LoginURL = internal.LoginURL
	cfg.RateLimits = internal.RateLimits
	cfg.RegistrationTokenTTL = internal.RegistrationTokenTTL
	// Mirror JWT bearer defaults back; without this an omitted AssertionMaxAge rejects every grant.
	if jb, ij := cfg.JWTBearer, internal.JWTBearer; jb != nil && ij != nil {
		jb.ClientAssertionMaxAge = ij.ClientAssertionMaxAge
		jb.AssertionMaxAge = ij.AssertionMaxAge
		jb.ReplayCacheTTL = ij.ReplayCacheTTL
		jb.MaxActorChainDepth = ij.MaxActorChainDepth
		jb.JWKSCacheTTL = ij.JWKSCacheTTL
		jb.JWKSCacheMaxEntries = ij.JWKSCacheMaxEntries
		jb.JWKSFetchTimeout = ij.JWKSFetchTimeout
		for i := range jb.TrustedJWTIssuers {
			if i < len(ij.TrustedJWTIssuers) && len(jb.TrustedJWTIssuers[i].AllowedAlgorithms) == 0 {
				jb.TrustedJWTIssuers[i].AllowedAlgorithms = ij.TrustedJWTIssuers[i].AllowedAlgorithms
			}
		}
	}
	if cfg.CIBA != nil && internal.CIBA != nil {
		cfg.CIBA.DefaultExpiry = internal.CIBA.DefaultExpiry
		cfg.CIBA.DefaultInterval = internal.CIBA.DefaultInterval
		cfg.CIBA.MaxRequestedExpiry = internal.CIBA.MaxRequestedExpiry
		cfg.CIBA.MinPollInterval = internal.CIBA.MinPollInterval
	}
	return nil
}

// OAuthState is the per-flow record kept between /start and /callback.
type OAuthState = internaloauth.State

// OAuthStateStore holds OAuth flow state between /start and /callback. Implement it over a shared
// store (Redis, SQL) to run several replicas; the default in-memory store is single-process.
type OAuthStateStore = internaloauth.StateStore

// NewMemoryOAuthStateStore returns the default in-process OAuthStateStore. Call Close when done.
func NewMemoryOAuthStateStore() *internaloauth.MemoryStateStore {
	return internaloauth.NewMemoryStateStore()
}

// OAuthSignupPolicy decides whether an OAuth sign-in may create a new user.
type OAuthSignupPolicy string

const (
	// OAuthSignupOpen lets any provider-authenticated identity create an account (the default).
	OAuthSignupOpen OAuthSignupPolicy = "open"
	// OAuthSignupClosed refuses to create users from OAuth; only existing users and linked accounts can sign in.
	OAuthSignupClosed OAuthSignupPolicy = "closed"
	// OAuthSignupAllowedDomains creates users only when the verified email domain is in AllowedEmailDomains.
	OAuthSignupAllowedDomains OAuthSignupPolicy = "allowed_domains"
	// OAuthSignupInvite creates users only when OAuthConfig.InviteCheck approves the verified email.
	OAuthSignupInvite OAuthSignupPolicy = "invite"
)

// OAuthConfig tunes OAuth login hardening. The zero value keeps v2 behavior: in-memory state, 10 minute TTL,
// no return-to parameter and open signup.
type OAuthConfig struct {
	StateStore OAuthStateStore
	StateTTL   time.Duration
	// AllowedReturnTo lists post-login destinations a caller may request with ?return_to= (exact URLs,
	// or "/" paths matched exactly or by a "*" prefix). Anything else falls back to
	// Config.PostLoginRedirect.
	AllowedReturnTo     []string
	Signup              OAuthSignupPolicy
	AllowedEmailDomains []string
	// InviteCheck is required for OAuthSignupInvite. It receives the verified, lower-cased email.
	InviteCheck func(ctx context.Context, email string) (bool, error)
	// RedirectURI, when set, builds the redirect_uri sent to the provider instead of BaseURL + prefix
	// + callback, so callback URLs already registered at the provider keep working. It must be an
	// absolute https URL (http only for loopback or with AllowInsecureRedirectURI) with no fragment or
	// userinfo. Never derive it from an unvalidated Host header.
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

// LoginThrottleEntryDeleter is the optional LoginThrottleStore capability that
// lets ResetPasswordAdmin clear an email's backoff entries across all client IPs.
type LoginThrottleEntryDeleter = throttle.LoginEntryDeleter

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

// BootstrapConfig gates creation of the first user behind a one-time setup token (the storage must
// implement UserCountStorage). While no user exists, password signup needs the token in the
// X-Setup-Token header or a "setupToken" body field. Afterwards signup is refused with
// CodeSignupClosed unless OpenSignupAfterFirstUser is set. Magic-link signup cannot present a
// token, so the first admin signs up with a password.
type BootstrapConfig = bootstrap.Config
