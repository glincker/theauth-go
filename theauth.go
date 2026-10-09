package theauth

import (
	"context"
	"crypto/ed25519"
	"net/netip"
	"sync/atomic"
	"strings"
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
	internalwebauthn "github.com/glincker/theauth-go/v2/internal/webauthn"
	"github.com/glincker/theauth-go/v2/kv"
)

// Config holds the wiring for a TheAuth instance.
//
// BaseURL and exactly one of Storage or CoreStorage are required. Everything else has sensible defaults
// applied by New: SessionTTL=24h, MagicLinkTTL=15m, CookieName="theauth_session",
// EmailSender=email.Noop{}. SigningKey is reserved for future JWT signing (v0.2+);
// v0.1 uses opaque tokens and leaves the field nil.
type Config struct {
	Storage Storage
	// CoreStorage is the alternative to Storage for adapters that implement
	// only the capabilities the enabled features need. It must cover users,
	// sessions, magic links and passwords; New returns
	// ErrStorageMissingCapability when an enabled feature needs more.
	CoreStorage CoreStorage
	storageRaw  any
	EmailSender email.Sender
	BaseURL     string
	// PathPrefix is the route prefix Mount and Handler serve under, and the
	// prefix of every URL the library generates. Default "/auth". It must
	// start with "/" and not end with one, for example "/api/v1/auth".
	PathPrefix string
	SigningKey ed25519.PrivateKey
	// SessionTTL is the absolute session lifetime. Defaults to 24h.
	SessionTTL time.Duration
	// SessionIdleTimeout expires a session unused for this long. Zero
	// disables it. Needs a storage implementing SessionManagementStorage.
	SessionIdleTimeout time.Duration
	// SessionTouchInterval throttles last-seen writes to at most one per
	// session per interval. Defaults to 1m; negative disables last-seen
	// tracking. Must be shorter than SessionIdleTimeout when that is set.
	SessionTouchInterval time.Duration
	// StepUpTTL is how long a successful POST /auth/step-up elevates a
	// session. Defaults to 5m.
	StepUpTTL time.Duration
	// SessionLinks enables programmatic session links when non-nil. Needs a
	// storage implementing SessionLinkStorage and SessionManagementStorage.
	SessionLinks *SessionLinksConfig
	MagicLinkTTL time.Duration
	CookieName   string
	// SecureCookie forces the Secure attribute on every session cookie. It
	// defaults to true when BaseURL is https. When false, Secure is still
	// set per request if BaseURL is https, the
	// connection is TLS, or a TrustedProxies peer sent X-Forwarded-Proto: https.
	SecureCookie bool
	// SuppressSecureCookieWarning silences the v2.2 deprecation WARN logged
	// when SecureCookie is false. Set this to true in local/dev environments
	// that run without TLS so the startup log stays clean. In production,
	// prefer enabling SecureCookie instead.
	SuppressSecureCookieWarning bool
	// RateLimitPerIP is the per-IP per-minute budget applied to credential
	// endpoints (signup/signin/forgot/reset). Defaults to 5 when zero.
	RateLimitPerIP int
	// RateLimitPerEmail is the per-email per-minute budget applied to signin
	// + forgot. Defaults to 3 when zero.
	RateLimitPerEmail int

	// TrustedProxies is the operator-supplied allowlist of reverse-proxy
	// networks whose X-Forwarded-For header is trusted by the rate
	// limiter and the audit IP capture path. Default: empty slice (no
	// XFF trust). Existing deployments that depend on XFF must opt in
	// explicitly by listing their reverse-proxy CIDR(s) here (security
	// audit H4, 2026-06-20).
	//
	// Example values: netip.MustParsePrefix("10.0.0.0/8"),
	// netip.MustParsePrefix("172.16.0.0/12"). For a single-host LB front
	// end pass a /32 (or /128 for IPv6) literal.
	TrustedProxies []netip.Prefix

	// Stores plugs in the shared state backends: the rate limiter behind
	// RateLimitByIP, RateLimitByEmail and the AS endpoint limits, the DPoP
	// proof replay cache, and the CIMD document cache. Nil fields keep the
	// in-process defaults, which are per replica. Behind several replicas set
	// them to a shared adapter (kv.FromCache(sqlkv or kv/redis)) so limits and
	// replay protection hold across instances. See the kv package.
	Stores kv.Stores

	// TrustedOrigins lists extra origins (scheme://host[:port]) allowed to
	// send cookie-authenticated state-changing requests. The BaseURL origin
	// is always trusted. Cross-origin SPAs on a sibling domain add theirs here.
	TrustedOrigins []string

	// DisableCSRFProtection turns off the Origin/Referer check on
	// cookie-authenticated POST/PUT/PATCH/DELETE requests. Leave false
	// unless a fronting layer already enforces it.
	DisableCSRFProtection bool

	// SuppressTrustedProxiesWarning silences the startup WARN logged when
	// TrustedProxies is empty. Set it when the server is exposed directly
	// with no reverse proxy in front.
	SuppressTrustedProxiesWarning bool

	// Providers is the list of OAuth providers exposed under
	// /auth/providers/{name}/start and /callback. Leave nil to disable
	// OAuth entirely (v0.1 / v0.2 behavior). Each provider's Name() must
	// be unique within the slice.
	Providers []Provider

	// ProviderResolver, when set, supplies OAuth/OIDC providers that are not
	// in Providers, looked up per request by name. Static providers win
	// unless ProviderResolverFirst is set. A resolver error fails the flow
	// closed. EncryptionKey is required when a resolver is set.
	ProviderResolver ProviderResolver
	// ProviderResolverFirst makes the resolver take precedence over Providers.
	ProviderResolverFirst bool
	// ProviderResolverTTL caches resolver answers, including "not found",
	// for this long. Zero disables caching; use InvalidateProvider to
	// drop an entry early.
	ProviderResolverTTL time.Duration

	// EncryptionKey is the 32-byte AES-256 key used to encrypt provider
	// access/refresh tokens before they hit storage. Required when
	// len(Providers) > 0; New returns an error otherwise. Source this from
	// a secrets manager; never commit it.
	EncryptionKey []byte

	// PostLoginRedirect is where the OAuth callback handler 302s to after
	// a successful sign-in. Defaults to "/" when empty. Set to a path on
	// your own origin; cross-origin redirects are not validated here.
	PostLoginRedirect string

	// APITokens enables scoped API tokens, RequireAbility and, via its Device
	// field, the device authorization grant. Needs APITokenStorage (and
	// DeviceCodeStorage for Device).
	APITokens *APITokensConfig

	// WebAuthn enables passkey registration + discoverable login when non-nil.
	// RPID and RPOrigins are mandatory per spec. Leave nil to keep v0.4 behavior.
	WebAuthn *WebAuthnConfig

	// OAuth tunes OAuth login hardening: state store, return-to allow-list
	// and signup policy. Nil keeps the defaults documented on OAuthConfig.
	OAuth *OAuthConfig

	// AuthEventSink, when set, receives every security-relevant
	// authentication event (login, MFA, password, passkey, TOTP, session,
	// token) as a PII-minimal AuthEvent. Independent of Config.Audit.
	AuthEventSink AuthEventSink

	// TOTP enables time-based second-factor enrollment + verification when non-nil.
	// Requires Config.EncryptionKey (already required by v0.3 OAuth) so the stored
	// secret is encrypted at rest. New returns an error if TOTP is set without a key.
	TOTP *TOTPConfig

	// Organizations (v0.7) enables multi-tenancy when non-nil. Single-tenant
	// deployments leave this nil; organization-scoped routes (SAML connection
	// CRUD, SCIM token CRUD, /auth/orgs/*) are not mounted.
	Organizations *OrganizationsConfig

	// SAML (v0.7) enables the per-connection Service Provider routes when
	// non-nil. The SP keypair lives on the config so multi-tenant deployments
	// can rotate it centrally; every connection signs AuthnRequests with this
	// single keypair. Requires Organizations to be non-nil.
	SAML *SAMLConfig

	// SCIM (v0.7) enables the /scim/v2 endpoints when non-nil. Requires
	// Organizations to be non-nil.
	SCIM *SCIMConfig

	// RBAC (v1.0) enables organization-scoped role and permission
	// management when non-nil. The zero value RBACConfig{} accepts the
	// seeded permissions and default org roles documented in
	// service_rbac.go; consumers extend (never shrink) the seeded lists.
	// New returns an error if Admin is non-nil and RBAC is nil because the
	// admin endpoints are permission-gated and meaningless without RBAC.
	RBAC *RBACConfig

	// Audit (v1.0) enables the async batched audit writer when non-nil.
	// When nil, EmitAudit is a silent no-op and no writer goroutine starts;
	// the v0.7 stub call sites keep working as no-ops, so deployments that
	// do not configure audit continue to behave exactly as before.
	Audit *AuditConfig

	// Admin (v1.0) mounts /admin/v1/* when non-nil. Requires RBAC to be
	// non-nil. The PathPrefix can be moved (e.g. "/api/admin/v1") but the
	// trailing version segment is always v1.
	Admin *AdminConfig

	// AuthorizationServer (v2.0 phase 1 + 2) enables the OAuth 2.1 + MCP
	// authorization server. When non-nil, /.well-known/oauth-authorization-server,
	// /oauth/authorize, /oauth/token, /oauth/revoke, /oauth/introspect,
	// /oauth/register, and /oauth/jwks are mounted. Requires
	// Config.EncryptionKey (32 bytes) and a Storage that satisfies
	// OAuthServerStorage.
	AuthorizationServer *AuthorizationServerConfig

	// AgentIdentity (v2.0 phase 3 + 4) enables the agent identity service
	// surface (Create / Rotate / Suspend / Resume / Revoke), the
	// client_credentials grant on /oauth/token, the delegation_grants
	// service surface, and the RFC 8693 token-exchange grant on /oauth/token.
	// Requires AuthorizationServer to be non-nil. Defaults applied at New:
	// MaxChainDepth=3, MaxDelegationDuration=90d, DefaultDelegatedTokenTTL=15m,
	// AgentSecretLength=32.
	AgentIdentity *AgentConfig

	// RevocationBus carries revocation events to long-lived connections.
	// Defaults to an in-process bus; supply one backed by Postgres NOTIFY or
	// Redis when streams and revokes can land on different processes.
	RevocationBus RevocationBus

	// AccountUX (v2.0 phase 6) mounts /account/agents and /account/delegations
	// when true. Requires AgentIdentity to be configured. Routes are gated by
	// session cookie auth only (no special permission): they manage the
	// authenticated user's own agents and the user's own granted delegations.
	AccountUX bool

	// Observability optionally wires consumer-supplied Tracer + Metrics
	// adapters. When nil the library uses no-op adapters and emits no
	// spans or metrics. The adapter pattern keeps OpenTelemetry,
	// Prometheus, and every other vendor out of theauth-go/go.mod;
	// consumers pick the stack they want and bridge it via the
	// Tracer/Metrics interfaces re-exported from this package.
	//
	// See observability.go for the re-exported types and
	// examples/observability-otel + examples/observability-prom for
	// reference implementations.
	Observability *Hooks

	// PasswordPolicy controls optional extensions to the password-verification
	// path. The zero value is safe (all extensions disabled).
	PasswordPolicy PasswordPolicyConfig

	// LifecycleHooks (v2.5) lets consumers react to authentication-lifecycle
	// events (signup, signin, password change, MFA enable, token issuance,
	// org switch) without forking handlers or wrapping every endpoint at the
	// HTTP boundary. Optional; nil is a silent no-op. See the LifecycleHooks
	// type doc for semantics, error handling, and current wiring status.
	LifecycleHooks *LifecycleHooks

	// Tenancy (v2.5) wires opt-in tenant-provisioning behavior. When
	// Tenancy.AutoCreatePersonalOrg is true and Config.Organizations is
	// also non-nil, every signup automatically creates a personal
	// organization, adds the user as its owner, and sets the session's
	// active organization to it. Removes the SQL-seeding friction
	// consumers previously hit on first signup. Nil = no auto-provisioning.
	Tenancy *TenancyConfig

	// LoginThrottle tunes password-login backoff, per-user lockout and the
	// per-user TOTP/recovery-code attempt limit. Nil selects safe defaults
	// (enabled); set LoginThrottle.Disabled to opt out.
	LoginThrottle *LoginThrottleConfig

	// Bootstrap, when non-nil, closes public signup and requires a one-time
	// setup token to create the first user. Needs a storage implementing
	// UserCountStorage.
	Bootstrap *BootstrapConfig

	// EmailNFKC additionally applies Unicode NFKC folding when canonicalizing
	// email addresses. Trimming and lowercasing always apply.
	EmailNFKC bool
}

// PasswordPolicyConfig holds optional password-verification extensions.
// These are designed for migration windows; disable them once users have
// been migrated and re-hashed.
type PasswordPolicyConfig struct {
	// AllowLegacyBcrypt enables the legacy-hash fallback in VerifyPassword for
	// migrated users. When true, bcrypt hashes ("$2a$", "$2b$", "$2x$", from
	// Auth0 and others) and PBKDF2 hashes ("$pbkdf2-sha256$", "$pbkdf2-sha512$",
	// from Keycloak) are verified. On a successful match the password is
	// transparently re-hashed with Argon2id and persisted by the library;
	// hosts that mirror hashes can observe it via OnLegacyHashAccepted.
	// With false, a bcrypt hash fails as invalid credentials. Set to false (default) in all non-migration deployments.
	AllowLegacyBcrypt bool

	// HashConcurrency bounds how many Argon2id hashes or verifications run at
	// once across the process; extra sign-ins wait their turn instead of each
	// allocating 64 MiB. Default NumCPU/4 (at least 1), which measured as the
	// throughput knee. The bound is process-wide, the last New call wins.
	HashConcurrency int

	// MinLength is the minimum password length in bytes. Default 12.
	MinLength int

	// MaxBytes is the maximum password length in bytes. Longer passwords are
	// rejected with CodeWeakPassword (HTTP 400). Default 72, the bcrypt limit.
	MaxBytes int

	// BreachChecker, when set, rejects passwords found in a breach corpus on
	// signup and password change. Lookup errors fail open. Default nil (off).
	BreachChecker BreachChecker

	// OnLegacyHashAccepted is invoked after the library has persisted the new
	// Argon2id hash for a user who signed in or stepped up with a legacy
	// bcrypt hash, from a separate goroutine, with (userID, newArgon2idHash).
	// A host that mirrors password hashes can update its own copy. The
	// library does not need it to work, so leaving it nil is fine. It is not
	// called if the rehash or persist failed, a panic in it is recovered and
	// logged, and it never blocks or fails the login.
	OnLegacyHashAccepted func(userID string, newArgon2idHash string)
}

// TheAuth is the public entry point, constructed once at app start and
// shared across handlers.
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
	rateLimitPerIP    int
	rateLimitPerEmail int
	trustedProxies    []netip.Prefix
	stores            kv.Stores
	rlSeq             atomic.Uint32
	trustedOrigins    []string
	csrfDisabled      bool
	apiTokens         *apitokens.Service
	revocations       RevocationBus

	storageRaw any
	doctorCfg  Config
	emailNorm  emailnorm.Normalizer
	throttle   *throttle.Limiter
	bootstrap  *bootstrap.Gate

	// dcrRegistrationTokenHashes is the sha256-hashed set of operator
	// initial access tokens accepted by POST /oauth/register when DCR is
	// bearer gated. Compares run with crypto/subtle.ConstantTimeCompare so
	// token-presence timing is not observable. Empty when no tokens are
	// configured; the handler then rejects every Authorization-bearing
	// request (security audit H1, 2026-06-20).
	dcrRegistrationTokenHashes [][32]byte

	// OAuth (v0.3). oauthSvc owns the start/callback state machine (GC
	// goroutine, PKCE state, provider dispatch). Nil when no Providers are
	// configured. PR H (2026-06-22): extracted from root service_oauth.go
	// into internal/oauth.Service; root keeps thin forwarder methods.
	providers         map[string]Provider
	providerReg       *internaloauth.Registry
	encryptionKey     []byte
	postLoginRedirect string
	oauthSvc          *internaloauth.Service
	authEventSink     AuthEventSink

	// WebAuthn (v0.5). webauthnCfg is the original Config.WebAuthn pointer
	// kept as a nil-signal for mount() and to give the handler access to
	// ChallengeTTL for the bridging cookie. The runtime state (in-flight
	// challenges + GC goroutine) lives on webauthnSvc.
	webauthnCfg *WebAuthnConfig
	// totpCfg is the original Config.TOTP pointer kept as a nil-signal
	// for mount(). The runtime state (enrollments + failure counters + GC
	// goroutine) lives on totpSvc.
	totpCfg *TOTPConfig

	// v0.7
	orgsCfg *OrganizationsConfig
	// samlCfg is the original Config.SAML pointer kept as a nil-signal
	// for mount(). The SP keypair, AuthnRequest in-flight map, and GC
	// goroutine live on samlSvc.
	samlCfg *SAMLConfig
	scimCfg *SCIMConfig

	// v1.0
	rbacCfg          *RBACConfig
	auditCfg         *AuditConfig
	adminCfg         *AdminConfig
	permCatalog      []Permission          // immutable snapshot for validation
	permIndex        map[string]Permission // name -> Permission, lookup cache
	defaultRoleSeeds []RoleSeed

	// v2.0 phase 1 + 2: OAuth 2.1 authorization server runtime state.
	// Nil when Config.AuthorizationServer is not set. PR B architecture
	// reorg (2026-06-20): the *asState struct and every per-method entry
	// point moved to internal/as as a unit. Root keeps thin forwarders
	// per public *TheAuth method so the v2.0 stability surface is
	// unchanged.
	as *internalas.Service

	// v2.0 phase 3 + 4: agent identity + delegation policy. Nil when
	// Config.AgentIdentity is not set; client_credentials and token-exchange
	// grants short-circuit with unsupported_grant_type in that case.
	agentCfg *AgentConfig

	// v2.0 phase 6: end-user self-service UX. When true, /account/agents and
	// /account/delegations are mounted. Requires agentCfg to be non-nil.
	accountUX bool

	// v2.5 lifecycle hooks. Never nil after New: substituted with
	// &LifecycleHooks{} when Config.LifecycleHooks is nil so forwarders can
	// dispatch without nil-checking the pointer. Individual function fields
	// MAY still be nil; the runHook helper handles that.
	lifecycle *LifecycleHooks

	// v2.5 tenancy auto-provisioning policy. Nil-safe: forwarders gate on
	// nil before calling autoProvisionPersonalOrg.
	tenancyCfg *TenancyConfig

	// hooks is the consumer-supplied observability bundle. Never nil: the
	// constructor substitutes &Hooks{} when Config.Observability is nil so
	// internal services can call hooks.StartSpan / hooks.Counter without
	// nil-checking the pointer itself. The fields inside (Tracer, Metrics)
	// MAY still be nil; the nil-safe helpers on *Hooks handle that path.
	hooks *Hooks

	// PR A architecture reorg (2026-06): low-complexity services are
	// extracted into internal packages and held here. Root methods on
	// *TheAuth forward to these so the v1.0/v2.0 public surface keeps the
	// exact same method signatures. Each internal package declares its own
	// minimal Storage interface so the constructor cycle stays broken.
	sessionSvc *session.Service
	magicSvc   *magiclink.Service
	scimSvc    *internalscim.Service
	orgsSvc    *organizations.Service
	rbacSvc    *rbac.Service

	// PR C architecture reorg (2026-06-20): agent identity + delegation
	// services. Nil when Config.AuthorizationServer is not set; the
	// service_agent.go and service_delegation.go forwarders short-circuit
	// against agentCfg in that case. Each package declares its own
	// minimal Storage interface so the constructor cycle stays broken
	// and the PR B oauthStorage back-door is gone for good.
	agentSvc      *agent.Service
	delegationSvc *delegation.Service

	// PR D architecture reorg (2026-06-20): high-complexity services
	// (password, totp, webauthn, saml, audit) are extracted into internal
	// packages and held here. Each internal package owns its own runtime
	// state (in-flight challenges / enrollments / AuthnRequests + GC
	// goroutines + audit writer goroutine) and declares its own minimal
	// Storage interface. Root methods on *TheAuth forward to these so the
	// public surface is byte-stable.
	sx          *sessionExt
	passwordSvc *password.Service
	totpSvc     *internaltotp.Service
	webauthnSvc *internalwebauthn.Service
	samlSvc     *internalsaml.Service
	auditSvc    *internalaudit.Service
	// v2.3 identity-linking service. Non-nil whenever at least one OAuth
	// provider or password auth is configured (which covers essentially all
	// deployments). Gated at account handler mount time so non-AccountUX
	// consumers are unaffected.
	identityLinkSvc *identitylink.Service
}

// New validates the Config, applies defaults, and returns a ready TheAuth.
// Validation and service wiring are delegated to helpers in wiring.go so
// this function stays a short orchestrator.
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
		storage:           cfg.Storage,
		emailSender:       cfg.EmailSender,
		baseURL:           cfg.BaseURL,
		allowLegacyBcrypt: cfg.PasswordPolicy.AllowLegacyBcrypt,
		onLegacyHash:      cfg.PasswordPolicy.OnLegacyHashAccepted,
		pathPrefix:        pathprefix.Normalize(cfg.PathPrefix),
		signingKey:        cfg.SigningKey,
		sessionTTL:        cfg.SessionTTL,
		sx:                sx,
		magicLinkTTL:      cfg.MagicLinkTTL,
		cookieName:        cfg.CookieName,
		revocations:       cfg.RevocationBus,
		// Secure defaults to on whenever BaseURL is https.
		secureCookie:               cfg.SecureCookie || strings.HasPrefix(strings.ToLower(cfg.BaseURL), "https://"),
		rateLimitPerIP:             cfg.RateLimitPerIP,
		rateLimitPerEmail:          cfg.RateLimitPerEmail,
		trustedProxies:             append([]netip.Prefix(nil), cfg.TrustedProxies...),
		stores:                     cfg.Stores,
		trustedOrigins:             trustedOrigins,
		csrfDisabled:               cfg.DisableCSRFProtection,
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
	return a, nil
}

// Start spawns the audit writer goroutine when Config.Audit is non-nil
// and the writer is not already running. Idempotent; safe to call
// multiple times. New calls Start automatically so existing callers that
// never invoked Start keep working.
//
// PR D architecture reorg (2026-06-20): forwards to the extracted audit
// service. WebAuthn / TOTP / SAML GC loops are spawned directly in New
// via their per-service Start methods; Close handles their lifecycle.
func (a *TheAuth) Start() error {
	if a.auditSvc == nil {
		return nil
	}
	return a.auditSvc.Start()
}

// Close releases background resources started by New: the OAuth state GC
// loop (v0.3), the WebAuthn challenge / TOTP enrollment GC loops (v0.5),
// the SAML AuthnRequest GC loop (v0.7), and the audit writer goroutine
// (v1.0). Audit drain waits up to Config.Audit.DrainTimeout (default 5
// seconds) for the writer to flush. Safe to call multiple times.
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
