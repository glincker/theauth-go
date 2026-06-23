package theauth

import (
	"crypto/ed25519"
	"net/netip"
	"time"

	"github.com/glincker/theauth-go/email"
	"github.com/glincker/theauth-go/internal/agent"
	internalas "github.com/glincker/theauth-go/internal/as"
	internalaudit "github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/delegation"
	"github.com/glincker/theauth-go/internal/identitylink"
	"github.com/glincker/theauth-go/internal/magiclink"
	internaloauth "github.com/glincker/theauth-go/internal/oauth"
	"github.com/glincker/theauth-go/internal/organizations"
	"github.com/glincker/theauth-go/internal/password"
	"github.com/glincker/theauth-go/internal/rbac"
	internalsaml "github.com/glincker/theauth-go/internal/saml"
	internalscim "github.com/glincker/theauth-go/internal/scim"
	"github.com/glincker/theauth-go/internal/session"
	internaltotp "github.com/glincker/theauth-go/internal/totp"
	internalwebauthn "github.com/glincker/theauth-go/internal/webauthn"
)

// Config holds the wiring for a TheAuth instance.
//
// Storage and BaseURL are required. Everything else has sensible defaults
// applied by New: SessionTTL=24h, MagicLinkTTL=15m, CookieName="theauth_session",
// EmailSender=email.Noop{}. SigningKey is reserved for future JWT signing (v0.2+);
// v0.1 uses opaque tokens and leaves the field nil.
type Config struct {
	Storage      Storage
	EmailSender  email.Sender
	BaseURL      string
	SigningKey   ed25519.PrivateKey
	SessionTTL   time.Duration
	MagicLinkTTL time.Duration
	CookieName   string
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

	// Providers is the list of OAuth providers exposed under
	// /auth/providers/{name}/start and /callback. Leave nil to disable
	// OAuth entirely (v0.1 / v0.2 behavior). Each provider's Name() must
	// be unique within the slice.
	Providers []Provider

	// EncryptionKey is the 32-byte AES-256 key used to encrypt provider
	// access/refresh tokens before they hit storage. Required when
	// len(Providers) > 0; New returns an error otherwise. Source this from
	// a secrets manager; never commit it.
	EncryptionKey []byte

	// PostLoginRedirect is where the OAuth callback handler 302s to after
	// a successful sign-in. Defaults to "/" when empty. Set to a path on
	// your own origin; cross-origin redirects are not validated here.
	PostLoginRedirect string

	// WebAuthn enables passkey registration + discoverable login when non-nil.
	// RPID and RPOrigins are mandatory per spec. Leave nil to keep v0.4 behavior.
	WebAuthn *WebAuthnConfig

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
}

// PasswordPolicyConfig holds optional password-verification extensions.
// These are designed for migration windows; disable them once users have
// been migrated and re-hashed.
type PasswordPolicyConfig struct {
	// AllowLegacyBcrypt enables the bcrypt fallback in VerifyPassword. When
	// true, hashes starting with "$2a$", "$2b$", or "$2x$" are verified with
	// golang.org/x/crypto/bcrypt. On a successful match the password is
	// transparently re-hashed with Argon2id; callers receive the new hash via
	// the OnLegacyHashAccepted callback so they can update storage
	// asynchronously. Set to false (default) in all non-migration deployments.
	AllowLegacyBcrypt bool

	// OnLegacyHashAccepted is called (in the background) whenever a bcrypt
	// hash is successfully verified and the password has been re-hashed. The
	// caller receives (userID string, newArgon2idHash string). Persist the new
	// hash to storage to complete the upgrade. If nil, upgrades are silently
	// discarded (not recommended for production migration windows).
	OnLegacyHashAccepted func(userID string, newArgon2idHash string)
}

// TheAuth is the public entry point, constructed once at app start and
// shared across handlers.
type TheAuth struct {
	storage           Storage
	emailSender       email.Sender
	baseURL           string
	signingKey        ed25519.PrivateKey
	sessionTTL        time.Duration
	magicLinkTTL      time.Duration
	cookieName        string
	secureCookie      bool
	rateLimitPerIP    int
	rateLimitPerEmail int
	trustedProxies    []netip.Prefix

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
	encryptionKey     []byte
	postLoginRedirect string
	oauthSvc          *internaloauth.Service

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

	providers, sp, dcrTokenHashes, err := validateConfig(&cfg)
	if err != nil {
		return nil, err
	}

	permCatalog, permIndex, defaultSeeds, err := validateRBAC(cfg.RBAC)
	if err != nil {
		return nil, err
	}

	a := &TheAuth{
		storage:                    cfg.Storage,
		emailSender:                cfg.EmailSender,
		baseURL:                    cfg.BaseURL,
		signingKey:                 cfg.SigningKey,
		sessionTTL:                 cfg.SessionTTL,
		magicLinkTTL:               cfg.MagicLinkTTL,
		cookieName:                 cfg.CookieName,
		secureCookie:               cfg.SecureCookie,
		rateLimitPerIP:             cfg.RateLimitPerIP,
		rateLimitPerEmail:          cfg.RateLimitPerEmail,
		trustedProxies:             append([]netip.Prefix(nil), cfg.TrustedProxies...),
		dcrRegistrationTokenHashes: dcrTokenHashes,
		providers:                  providers,
		encryptionKey:              cfg.EncryptionKey,
		postLoginRedirect:          cfg.PostLoginRedirect,
		webauthnCfg:                cfg.WebAuthn,
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
	}

	if err := wireServices(a, cfg, providers, sp); err != nil {
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
