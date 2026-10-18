package theauth

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/email"
	"github.com/glincker/theauth-go/v2/internal/agent"
	"github.com/glincker/theauth-go/v2/internal/apitokens"
	internalas "github.com/glincker/theauth-go/v2/internal/as"
	internalaudit "github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/bootstrap"
	"github.com/glincker/theauth-go/v2/internal/delegation"
	"github.com/glincker/theauth-go/v2/internal/emailnorm"
	"github.com/glincker/theauth-go/v2/internal/httpsec"
	"github.com/glincker/theauth-go/v2/internal/identitylink"
	"github.com/glincker/theauth-go/v2/internal/magiclink"
	internaloauth "github.com/glincker/theauth-go/v2/internal/oauth"
	"github.com/glincker/theauth-go/v2/internal/organizations"
	"github.com/glincker/theauth-go/v2/internal/password"
	"github.com/glincker/theauth-go/v2/internal/pathprefix"
	"github.com/glincker/theauth-go/v2/internal/ratelimit"
	"github.com/glincker/theauth-go/v2/internal/rbac"
	internalsaml "github.com/glincker/theauth-go/v2/internal/saml"
	internalscim "github.com/glincker/theauth-go/v2/internal/scim"
	"github.com/glincker/theauth-go/v2/internal/session"
	"github.com/glincker/theauth-go/v2/internal/testhooks"
	"github.com/glincker/theauth-go/v2/internal/throttle"
	internaltotp "github.com/glincker/theauth-go/v2/internal/totp"
	"github.com/glincker/theauth-go/v2/internal/trusteddevice"
	internalwebauthn "github.com/glincker/theauth-go/v2/internal/webauthn"
	"github.com/glincker/theauth-go/v2/kv"
)

// Config holds the wiring for a TheAuth instance. BaseURL and exactly one of Storage or CoreStorage
// are required; New applies the other defaults. SigningKey is reserved for future JWT signing (v0.1
// uses opaque tokens).
type Config struct {
	Storage Storage
	// CoreStorage is the alternative to Storage for adapters that implement only the capabilities
	// enabled features need. New returns ErrStorageMissingCapability when a feature needs more.
	CoreStorage CoreStorage
	storageRaw  any
	EmailSender email.Sender
	BaseURL     string
	// PathPrefix is the route prefix Mount and Handler serve under (default "/auth"). It must start
	// with "/" and not end with one.
	PathPrefix string
	SigningKey ed25519.PrivateKey
	SessionTTL time.Duration
	// SessionIdleTimeout expires a session unused for this long; zero disables it. Needs
	// SessionManagementStorage.
	SessionIdleTimeout time.Duration
	// SessionTouchInterval throttles last-seen writes (default 1m; negative disables). Must be shorter
	// than SessionIdleTimeout.
	SessionTouchInterval time.Duration
	StepUpTTL            time.Duration
	// SessionLinks enables programmatic session links when non-nil. Needs SessionLinkStorage and
	// SessionManagementStorage.
	SessionLinks *SessionLinksConfig
	MagicLinkTTL time.Duration
	CookieName   string
	// SecureCookie forces the Secure attribute on session cookies. It defaults to true when BaseURL is
	// https; otherwise Secure is still set per request when the connection is TLS or a trusted proxy
	// sent X-Forwarded-Proto: https.
	SecureCookie bool
	// SuppressSecureCookieWarning silences the startup WARN logged when SecureCookie is false. Use it
	// only for local dev without TLS.
	SuppressSecureCookieWarning bool
	// Cookies tunes the attributes of every cookie the library writes (session, trusted device, OAuth
	// state, WebAuthn challenge). The zero value keeps the historic behavior. See CookiesConfig.
	Cookies CookiesConfig
	// SecurityHeaders adds Strict-Transport-Security (https requests only), X-Content-Type-Options,
	// Referrer-Policy and X-Frame-Options to every response served through Mount or Handler. It is off
	// by default so an embedding application keeps control of its own headers.
	SecurityHeaders bool
	// RateLimitPerIP is the per-IP per-minute budget for credential endpoints (default 5).
	RateLimitPerIP int
	// RateLimitPerEmail is the per-email per-minute budget for signin and forgot (default 3).
	RateLimitPerEmail int

	// TrustedProxies lists reverse-proxy networks whose X-Forwarded-For is trusted by the rate limiter
	// and the audit IP capture. Default empty (no XFF trust); deployments that depend on XFF must list
	// their proxy CIDRs (security audit H4). For a single-host load balancer pass a /32 (or /128)
	// prefix.
	TrustedProxies []netip.Prefix

	// Stores plugs in shared state backends: the rate limiters, the DPoP replay cache and the CIMD
	// cache. Nil fields keep per-replica in-process defaults. Behind several replicas, use a shared
	// adapter (see the kv package).
	Stores kv.Stores

	// TrustedOrigins lists extra origins (scheme://host[:port]) allowed to send cookie-authenticated
	// state-changing requests. The BaseURL origin is always trusted.
	TrustedOrigins []string

	// DisableCSRFProtection turns off the Origin/Referer check on cookie-authenticated unsafe methods.
	// Leave false unless a fronting layer enforces it.
	DisableCSRFProtection bool

	// Admission, when set, runs the Admission middleware ahead of every route Mount and Handler
	// register. It stacks with the per-route credential limits.
	Admission *AdmissionOptions

	// ErrorResponder, when set, writes every error response the root middleware produces, so an app
	// can emit its own envelope. status is the HTTP status, code the stable machine code and message
	// the text. The WWW-Authenticate header is already set on a 401. Nil keeps the built-in RFC 7807
	// bodies.
	ErrorResponder func(w http.ResponseWriter, r *http.Request, status int, code, message string)

	// SuppressTrustedProxiesWarning silences the startup WARN logged when TrustedProxies is empty.
	SuppressTrustedProxiesWarning bool

	// Providers is the list of OAuth providers exposed under /auth/providers/{name}/start and
	// /callback. Nil disables OAuth. Each Name() must be unique.
	Providers []Provider

	// ProviderResolver supplies OAuth/OIDC providers not in Providers, looked up per request by name.
	// Static providers win unless ProviderResolverFirst is set. A resolver error fails the flow
	// closed. EncryptionKey is required with it.
	ProviderResolver      ProviderResolver
	ProviderResolverFirst bool
	// ProviderResolverTTL caches resolver answers, including "not found". Zero disables caching; use
	// InvalidateProvider to drop an entry early.
	ProviderResolverTTL time.Duration

	// EncryptionKey is the 32-byte AES-256 key that encrypts provider tokens before storage. Required
	// when Providers is non-empty. Source it from a secrets manager; never commit it.
	EncryptionKey []byte

	// PostLoginRedirect is where the OAuth callback redirects after sign-in (default "/"). Set a path
	// on your own origin.
	PostLoginRedirect string

	// APITokens enables scoped API tokens, RequireAbility and, via its Device field, the device grant.
	APITokens *APITokensConfig

	// WebAuthn enables passkey registration and discoverable login when non-nil.
	WebAuthn *WebAuthnConfig

	OAuth *OAuthConfig

	// AuthEventSink, when set, receives every security-relevant authentication event as a PII-minimal AuthEvent.
	// It is independent of Config.Audit.
	AuthEventSink AuthEventSink

	// SharedSignals enables the OpenID Shared Signals Framework 1.0 transmitter and optional receiver. Requires
	// AuthorizationServer. See docs/shared-signals.md.
	SharedSignals *SharedSignalsConfig

	// TOTP enables time-based second-factor enrollment. Requires EncryptionKey so the secret is
	// encrypted at rest.
	TOTP *TOTPConfig

	// Organizations enables multi-tenancy when non-nil. Organization-scoped routes are not mounted otherwise.
	Organizations *OrganizationsConfig

	// SAML enables the per-connection Service Provider routes when non-nil. The SP keypair lives here
	// so it can rotate centrally. Requires Organizations.
	SAML *SAMLConfig

	// SCIM enables the /scim/v2 endpoints when non-nil. Requires Organizations.
	SCIM *SCIMConfig

	// RBAC enables organization-scoped role and permission management when non-nil. Consumers extend,
	// never shrink, the seeded lists. New fails if Admin is set without RBAC, since admin endpoints
	// are permission-gated.
	RBAC *RBACConfig

	// Audit enables the async batched audit writer when non-nil. When nil, EmitAudit is a silent no-op.
	Audit *AuditConfig

	// Admin mounts /admin/v1/* when non-nil. Requires RBAC.
	Admin *AdminConfig

	// AuthorizationServer enables the OAuth 2.1 and MCP authorization server, mounting the
	// /.well-known and /oauth routes. Requires EncryptionKey (32 bytes) and a Storage implementing
	// OAuthServerStorage.
	AuthorizationServer *AuthorizationServerConfig

	// AgentIdentity enables the agent identity service, the client_credentials grant, delegation
	// grants and RFC 8693 token exchange on /oauth/token. Requires AuthorizationServer. Defaults are
	// applied at New.
	AgentIdentity *AgentConfig

	// RevocationBus carries revocation events to long-lived connections. Defaults to an in-process
	// bus; supply one backed by Postgres NOTIFY or Redis when streams and revokes can land on
	// different processes.
	RevocationBus RevocationBus

	// AccountUX mounts /account/agents and /account/delegations. Requires AgentIdentity. Routes use
	// session auth only and manage the user's own agents and delegations.
	AccountUX bool

	// Observability optionally wires consumer-supplied Tracer and Metrics adapters. Nil uses no-op
	// adapters, which keeps OpenTelemetry and other vendor SDKs out of this module. See
	// examples/observability-otel and observability-prom.
	Observability *Hooks

	// PasswordPolicy controls optional extensions to password verification. The zero value disables them all.
	PasswordPolicy PasswordPolicyConfig

	// LifecycleHooks lets consumers react to authentication lifecycle events without forking handlers.
	// Nil is a no-op. See the LifecycleHooks type for semantics.
	LifecycleHooks *LifecycleHooks

	// Tenancy opts into tenant provisioning. When Tenancy.AutoCreatePersonalOrg is true and
	// Organizations is set, each signup creates a personal organization owned by the user and makes it
	// active.
	Tenancy *TenancyConfig

	// LoginThrottle tunes password-login backoff, per-user lockout and the TOTP attempt limit. Nil
	// selects safe defaults.
	LoginThrottle *LoginThrottleConfig

	// Bootstrap, when non-nil, closes public signup and requires a one-time setup token for the first
	// user. Needs UserCountStorage.
	Bootstrap *BootstrapConfig

	// EmailNFKC additionally applies Unicode NFKC folding when canonicalizing emails. Trimming and
	// lowercasing always apply.
	EmailNFKC bool

	// AccountState enforces per-user lifecycle flags (forced password change, disabled users) at every
	// sign-in. Needs AccountStateStorage.
	AccountState bool

	// AccountDeletion mounts DELETE /account when non-nil. The session must have authenticated recently.
	AccountDeletion *AccountDeletionConfig

	SessionPolicy *SessionPolicy

	TrustedDevices *TrustedDevicesConfig
}

// PasswordPolicyConfig holds optional password-verification extensions, meant for migration
// windows. Disable them once users are migrated and re-hashed.
type PasswordPolicyConfig struct {
	// AllowLegacyBcrypt enables the legacy-hash fallback for migrated users: bcrypt ($2a$, $2b$, $2x$)
	// and PBKDF2 hashes are verified and transparently re-hashed to Argon2id on success. With false a
	// bcrypt hash fails. Leave false outside migrations.
	AllowLegacyBcrypt bool

	// HashConcurrency bounds concurrent Argon2id hashes process-wide (default NumCPU/4, at least 1) so
	// sign-ins queue instead of each allocating 64 MiB. The last New call wins.
	HashConcurrency int

	// MinLength is the minimum password length in bytes (default 12).
	MinLength int

	// MaxBytes is the maximum password length in bytes, rejected with CodeWeakPassword (default 72,
	// the bcrypt limit).
	MaxBytes int

	// BreachChecker, when set, rejects passwords found in a breach corpus on signup and change. Lookup
	// errors fail open.
	BreachChecker BreachChecker

	// OnLegacyHashAccepted is called from a separate goroutine after a legacy-hash user's password is
	// re-hashed to Argon2id, with (userID, newHash), so hosts that mirror hashes can update their
	// copy. Panics are recovered; it never fails a login.
	OnLegacyHashAccepted func(userID string, newArgon2idHash string)
}

// TheAuth is the public entry point, constructed once at app start and shared across handlers.
type TheAuth struct {
	storage           Storage
	emailSender       email.Sender
	baseURL           string
	allowLegacyBcrypt bool
	onLegacyHash      func(userID, newArgon2idHash string)
	pathPrefix        string
	signingKey        ed25519.PrivateKey
	sessionTTL        time.Duration
	magicLinkTTL      time.Duration
	cookieName        string
	secureCookie      bool
	cookiePolicy      httpsec.CookiePolicy
	securityHeaders   bool
	rateLimitPerIP    int
	rateLimitPerEmail int
	trustedProxies    []netip.Prefix
	stores            kv.Stores
	rlSeq             atomic.Uint32
	trustedOrigins    []string
	csrfDisabled      bool
	admission         *AdmissionOptions
	errorResponder    func(w http.ResponseWriter, r *http.Request, status int, code, message string)
	apiTokens         *apitokens.Service
	revocations       RevocationBus

	storageRaw any
	doctorCfg  Config
	emailNorm  emailnorm.Normalizer
	throttle   *throttle.Limiter
	bootstrap  *bootstrap.Gate

	// dcrRegistrationTokenHashes holds the sha256 digests of operator initial access tokens for
	// bearer-gated DCR. Compares are constant time. Empty means the handler rejects every
	// Authorization-bearing request (security audit H1).
	dcrRegistrationTokenHashes [][32]byte

	// providers are the OAuth providers by name. The OAuth state machine lives in internal/oauth.
	providers         map[string]Provider
	providerReg       *internaloauth.Registry
	encryptionKey     []byte
	postLoginRedirect string
	oauthSvc          *internaloauth.Service
	authEventSink     AuthEventSink

	// webauthnCfg is the original Config.WebAuthn, kept as the nil signal for mount() and for
	// ChallengeTTL. The runtime state lives on webauthnSvc.
	webauthnCfg *WebAuthnConfig
	// totpCfg is the original Config.TOTP, kept as the nil signal for mount(). Runtime state lives on totpSvc.
	totpCfg *TOTPConfig

	orgsCfg *OrganizationsConfig
	// samlCfg is the original Config.SAML, kept as the nil signal for mount(). Runtime state lives on samlSvc.
	samlCfg *SAMLConfig
	scimCfg *SCIMConfig

	rbacCfg          *RBACConfig
	auditCfg         *AuditConfig
	adminCfg         *AdminConfig
	permCatalog      []Permission          // immutable snapshot for validation
	permIndex        map[string]Permission // name -> Permission, lookup cache
	defaultRoleSeeds []RoleSeed

	// as is the OAuth 2.1 authorization server service, nil when Config.AuthorizationServer is unset.
	// Root keeps thin forwarders per public method so the surface is unchanged.
	as *internalas.Service

	// signalsSvc is the Shared Signals transmitter and receiver, nil unless Config.SharedSignals is set.
	signalsSvc *sharedSignals

	// agentCfg is the original Config.AgentIdentity. Nil makes client_credentials and token exchange
	// return unsupported_grant_type.
	agentCfg *AgentConfig

	accountUX bool

	// lifecycle is never nil after New; it is substituted with an empty LifecycleHooks so forwarders
	// need no nil check.
	lifecycle *LifecycleHooks

	// tenancyCfg is the Tenancy policy. Nil-safe: callers gate on nil before auto-provisioning.
	tenancyCfg *TenancyConfig

	// hooks is the observability bundle, never nil: New substitutes an empty Hooks, and its nil-safe
	// helpers handle nil fields.
	hooks *Hooks

	// Low-complexity services are extracted into internal packages and held here. Each declares its
	// own minimal Storage interface so the constructor cycle stays broken.
	sessionSvc *session.Service
	magicSvc   *magiclink.Service
	scimSvc    *internalscim.Service
	orgsSvc    *organizations.Service
	rbacSvc    *rbac.Service

	// agentSvc and delegation services. Nil when AuthorizationServer is unset.
	agentSvc      *agent.Service
	agentGate     *agent.Gate
	delegationSvc *delegation.Service

	// sx holds the high-complexity services (password, totp, webauthn, saml, audit). Each owns its
	// runtime state and GC goroutines and declares its own minimal Storage interface, so the public
	// surface stays byte-stable.
	sx          *sessionExt
	passwordSvc *password.Service
	totpSvc     *internaltotp.Service
	webauthnSvc *internalwebauthn.Service
	samlSvc     *internalsaml.Service
	auditSvc    *internalaudit.Service
	// auditHasher hashes input content for provenance filters (Config.Audit.InputHashKey).
	auditHasher internalaudit.InputHasher
	// identityLinkSvc is non-nil whenever an OAuth provider or password auth is configured.
	identityLinkSvc *identitylink.Service

	// acct gates sign-in and reacts to password changes; devices backs remember-this-device; deletion
	// enables DELETE /account.
	acct         *accountLifecycle
	devices      *trusteddevice.Service
	deviceCookie string
	deletion     *AccountDeletionConfig
}

// New validates the Config, applies defaults, and returns a ready TheAuth. Validation and wiring
// are delegated to wiring.go so this function stays a short orchestrator.
func New(cfg Config) (*TheAuth, error) {
	applyConfigDefaults(&cfg)
	crypto.SetHashConcurrency(cfg.PasswordPolicy.HashConcurrency)

	providers, sp, dcrTokenHashes, err := validateConfig(&cfg)
	if err != nil {
		return nil, err
	}
	if cfg.CoreStorage != nil {
		cfg.Storage = assembleStorage(cfg.CoreStorage)
	}
	sx, err := newSessionExt(&cfg)
	if err != nil {
		return nil, err
	}

	permCatalog, permIndex, defaultSeeds, err := validateRBAC(cfg.RBAC)
	if err != nil {
		return nil, err
	}

	trustedOrigins, err := httpsec.NormalizeOrigins(cfg.TrustedOrigins)
	if err != nil {
		return nil, err
	}

	a := &TheAuth{
		storage:                    cfg.Storage,
		emailSender:                cfg.EmailSender,
		baseURL:                    cfg.BaseURL,
		allowLegacyBcrypt:          cfg.PasswordPolicy.AllowLegacyBcrypt,
		onLegacyHash:               cfg.PasswordPolicy.OnLegacyHashAccepted,
		pathPrefix:                 pathprefix.Normalize(cfg.PathPrefix),
		signingKey:                 cfg.SigningKey,
		sessionTTL:                 cfg.SessionTTL,
		sx:                         sx,
		magicLinkTTL:               cfg.MagicLinkTTL,
		cookieName:                 cfg.CookieName,
		revocations:                cfg.RevocationBus,
		secureCookie:               cfg.SecureCookie || strings.HasPrefix(strings.ToLower(cfg.BaseURL), "https://"),
		cookiePolicy:               cookiePolicyOf(&cfg),
		securityHeaders:            cfg.SecurityHeaders,
		rateLimitPerIP:             cfg.RateLimitPerIP,
		rateLimitPerEmail:          cfg.RateLimitPerEmail,
		trustedProxies:             append([]netip.Prefix(nil), cfg.TrustedProxies...),
		stores:                     cfg.Stores,
		trustedOrigins:             trustedOrigins,
		csrfDisabled:               cfg.DisableCSRFProtection,
		admission:                  cfg.Admission,
		errorResponder:             cfg.ErrorResponder,
		storageRaw:                 cfg.storageRaw,
		emailNorm:                  newEmailNormalizer(cfg.EmailNFKC),
		dcrRegistrationTokenHashes: dcrTokenHashes,
		providers:                  providers,
		encryptionKey:              cfg.EncryptionKey,
		postLoginRedirect:          cfg.PostLoginRedirect,
		webauthnCfg:                cfg.WebAuthn,
		authEventSink:              cfg.AuthEventSink,
		totpCfg:                    cfg.TOTP,
		orgsCfg:                    cfg.Organizations,
		samlCfg:                    cfg.SAML,
		scimCfg:                    cfg.SCIM,
		rbacCfg:                    cfg.RBAC,
		auditCfg:                   cfg.Audit,
		adminCfg:                   cfg.Admin,
		permCatalog:                permCatalog,
		permIndex:                  permIndex,
		defaultRoleSeeds:           defaultSeeds,
		agentCfg:                   cfg.AgentIdentity,
		accountUX:                  cfg.AccountUX,
		hooks:                      coalesceHooks(cfg.Observability),
		lifecycle:                  coalesceLifecycleHooks(cfg.LifecycleHooks),
		tenancyCfg:                 cfg.Tenancy,
	}
	a.doctorCfg = cfg
	if a.revocations == nil {
		a.revocations = NewMemoryRevocationBus()
	}

	if err := wireServices(a, cfg, providers, sp); err != nil {
		return nil, err
	}
	if a.apiTokens, err = apitokens.New(tokenHost{a}, cfg.APITokens, cfg.storageRaw, a.storage, a.baseURL); err != nil {
		return nil, err
	}
	if a.apiTokens != nil && cfg.ErrorResponder != nil {
		a.apiTokens.SetErrorResponder(cfg.ErrorResponder)
	}
	return a, nil
}

// Start spawns the audit writer goroutine when Config.Audit is set. It is idempotent. New calls it
// automatically.
func (a *TheAuth) Start() error {
	if a.auditSvc == nil {
		return nil
	}
	return a.auditSvc.Start()
}

// Close releases background resources: the OAuth state, WebAuthn, TOTP and SAML GC loops and the
// audit writer. Audit drain waits up to Config.Audit.DrainTimeout. Safe to call multiple times.
func (a *TheAuth) Close() {
	if a.oauthSvc != nil {
		a.oauthSvc.Stop()
	}
	if a.webauthnSvc != nil {
		a.webauthnSvc.Stop()
	}
	if a.totpSvc != nil {
		a.totpSvc.Stop()
	}
	if a.samlSvc != nil {
		a.samlSvc.Stop()
	}
	if a.signalsSvc != nil {
		a.signalsSvc.cancel()
	}
	if a.as != nil {
		a.as.Stop()
	}
	if a.auditSvc != nil {
		a.auditSvc.Stop()
	}
}

// Stats returns a snapshot of runtime counters.
func (a *TheAuth) Stats() Stats {
	if a.auditSvc == nil {
		return Stats{}
	}
	c := a.auditSvc.Counters()
	return Stats{
		AuditEmitted:    c.Emitted,
		AuditWritten:    c.Written,
		AuditDropped:    c.Dropped,
		AuditFailed:     c.Failed,
		AuditSinkFailed: c.SinkFailed,
	}
}

func init() {
	testhooks.ValidateEmail = validateEmail
	testhooks.IssueSession = func(a any, ctx context.Context, u User, ua, ip string) (string, Session, error) {
		return a.(*TheAuth).issueSession(ctx, u, ua, ip)
	}
	testhooks.ValidateSession = func(a any, ctx context.Context, token string) (*Session, *User, error) {
		return a.(*TheAuth).validateSession(ctx, token)
	}
	testhooks.RequestMagicLink = func(a any, ctx context.Context, email string) (string, error) {
		return a.(*TheAuth).requestMagicLinkForTest(ctx, email)
	}
	testhooks.ConsumeMagicLink = func(a any, ctx context.Context, token string) (string, *User, error) {
		return a.(*TheAuth).consumeMagicLink(ctx, token)
	}
	testhooks.SetBaseURL = func(a any, url string) { a.(*TheAuth).baseURL = url }
	testhooks.SignupWithPassword = func(a any, ctx context.Context, email, pw string) (*User, string, error) {
		return a.(*TheAuth).signupWithPassword(ctx, email, pw)
	}
	testhooks.SigninWithPassword = func(a any, ctx context.Context, email, pw, ua, ip string) (string, *User, error) {
		tok, u, _, err := a.(*TheAuth).signinWithPassword(ctx, email, pw, ua, ip)
		return tok, u, err
	}
	testhooks.RequestPasswordReset = func(a any, ctx context.Context, email string) (string, error) {
		return a.(*TheAuth).requestPasswordResetForTest(ctx, email)
	}
	testhooks.ResetPassword = func(a any, ctx context.Context, token, pw string) error {
		return a.(*TheAuth).resetPassword(ctx, token, pw)
	}
	testhooks.NewKeyedLimiter = func(perMinute int, evictAfter, tick time.Duration) testhooks.Limiter {
		return ratelimit.NewWith(perMinute, evictAfter, tick)
	}
	testhooks.LinkOAuth = func(a any, ctx context.Context, sessionToken, provider, pid string) error {
		return a.(*TheAuth).identityLinkSvc.LinkOAuthToCurrentUser(ctx, sessionToken, provider, pid, nil, nil, nil, "")
	}
	testhooks.LinkPassword = func(a any, ctx context.Context, sessionToken, pw string) error {
		return a.(*TheAuth).identityLinkSvc.LinkPasswordToCurrentUser(ctx, sessionToken, pw)
	}
	testhooks.MergeAccounts = func(a any, ctx context.Context, sessionToken string, secondary ULID) error {
		return a.(*TheAuth).identityLinkSvc.MergeAccounts(ctx, sessionToken, secondary, identitylink.MergeInput{})
	}
	testhooks.UnlinkOAuth = func(a any, ctx context.Context, sessionToken, provider string) error {
		return a.(*TheAuth).identityLinkSvc.UnlinkOAuthProvider(ctx, sessionToken, provider)
	}
	testhooks.SetAPITokenClock = func(a any, now func() time.Time) { a.(*TheAuth).apiTokens.SetClock(now) }
}
