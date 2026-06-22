package theauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/email"
	"github.com/glincker/theauth-go/internal/agent"
	internalas "github.com/glincker/theauth-go/internal/as"
	internalaudit "github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/delegation"
	"github.com/glincker/theauth-go/internal/magiclink"
	"github.com/glincker/theauth-go/internal/organizations"
	"github.com/glincker/theauth-go/internal/password"
	"github.com/glincker/theauth-go/internal/rbac"
	internalsaml "github.com/glincker/theauth-go/internal/saml"
	internalscim "github.com/glincker/theauth-go/internal/scim"
	"github.com/glincker/theauth-go/internal/session"
	internaltotp "github.com/glincker/theauth-go/internal/totp"
	internalwebauthn "github.com/glincker/theauth-go/internal/webauthn"
)

// Storage is the persistence contract TheAuth depends on. Adapters live in
// sub-packages (storage/memory, storage/postgres). Defined here so that
// service code in this package can reference it without importing the
// storage sub-package (which would create an import cycle, because storage
// imports this package for the model types).
//
// The storage package re-exports this as storage.Storage so consumers can
// keep importing it from the conventional location.
type Storage interface {
	// Users
	CreateUser(ctx context.Context, u User) (User, error)
	UserByEmail(ctx context.Context, email string) (*User, error)
	UserByID(ctx context.Context, id ULID) (*User, error)
	MarkEmailVerified(ctx context.Context, userID ULID) error

	// Sessions
	CreateSession(ctx context.Context, s Session) (Session, error)
	SessionByTokenHash(ctx context.Context, hash []byte) (*Session, error)
	RevokeSession(ctx context.Context, id ULID) error
	RevokeUserSessions(ctx context.Context, userID ULID) error

	// Magic links
	CreateMagicLink(ctx context.Context, ml MagicLink) error
	ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*MagicLink, error)

	// Email + password (v0.2)
	SetUserPassword(ctx context.Context, userID ULID, passwordHash string) error
	// UserByEmailWithPassword fetches a user along with their stored PHC hash.
	// passwordHash is "" if the account exists but has never set a password
	// (e.g. magic-link-only signup). Callers should treat empty hash as
	// "no password credential available" and surface invalid_credentials.
	UserByEmailWithPassword(ctx context.Context, email string) (user *User, passwordHash string, err error)
	CreatePasswordResetToken(ctx context.Context, t PasswordResetToken) error
	ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error)

	// OAuth accounts (v0.3)
	// UpsertOAuthAccount inserts or updates the row keyed by
	// (provider, provider_user_id). Returns the resulting row so callers
	// can use the assigned ID and timestamps. Implementations must encrypt
	// any token bytes before they reach storage; this layer only persists
	// what it is given.
	UpsertOAuthAccount(ctx context.Context, a OAuthAccount) (OAuthAccount, error)
	// OAuthAccountByProviderUserID looks up the row for a provider/user
	// pair. Returns ErrStorageNotFound when no row exists.
	OAuthAccountByProviderUserID(ctx context.Context, provider, providerUserID string) (*OAuthAccount, error)

	// Sessions: v0.5 step-up additions
	// CreateSessionWithAuthLevel mints a session whose AuthLevel column is
	// set to the supplied value (typically AuthLevelPending2FA). Mirrors
	// CreateSession otherwise. CreateSession itself continues to default
	// to AuthLevelFull at the DDL layer so older callers see no change.
	CreateSessionWithAuthLevel(ctx context.Context, s Session) (Session, error)
	// UpdateSessionAuthLevel rewrites a single session's AuthLevel column.
	// Used by /auth/totp/verify to promote a pending session to full.
	UpdateSessionAuthLevel(ctx context.Context, id ULID, level string) error

	// WebAuthn (v0.5)
	InsertWebAuthnCredential(ctx context.Context, c WebAuthnCredential) (WebAuthnCredential, error)
	WebAuthnCredentialsByUserID(ctx context.Context, userID ULID) ([]WebAuthnCredential, error)
	// WebAuthnCredentialByCredentialID returns the row keyed by the raw
	// authenticator credential ID, or ErrStorageNotFound when missing.
	WebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error)
	// UpdateWebAuthnSignCount atomically writes a strictly greater sign
	// count and bumps last_used_at. Returns ErrReplayDetected when the
	// new count is not strictly greater than the stored value (the
	// canonical replay signal per WebAuthn L2 / L3). Returns
	// ErrStorageNotFound when the credential does not exist.
	UpdateWebAuthnSignCount(ctx context.Context, credentialID []byte, newCount uint32, usedAt time.Time) error
	// DeleteWebAuthnCredential removes a credential by ID, scoped to the
	// owning user. Returns ErrStorageNotFound when the row does not exist
	// or does not belong to the caller (no leak on cross-user lookup).
	DeleteWebAuthnCredential(ctx context.Context, id ULID, userID ULID) error

	// TOTP (v0.5)
	// UpsertPendingTOTPSecret writes an encrypted secret with
	// confirmed_at = NULL. Replaces any prior unconfirmed secret for the
	// same user; preserves a confirmed one untouched (re-enrollment
	// requires DeleteTOTPSecret first).
	UpsertPendingTOTPSecret(ctx context.Context, s TOTPSecret) error
	// ConfirmTOTPSecret sets confirmed_at on the user's pending secret.
	// Returns ErrStorageNotFound when no pending row exists.
	ConfirmTOTPSecret(ctx context.Context, userID ULID, at time.Time) error
	TOTPSecretByUserID(ctx context.Context, userID ULID) (*TOTPSecret, error)
	DeleteTOTPSecret(ctx context.Context, userID ULID) error

	InsertRecoveryCodes(ctx context.Context, codes []RecoveryCode) error
	// ConsumeRecoveryCode walks the user's unused codes, locates the one
	// whose hash matches via crypto.VerifyRecoveryCode, and marks it used
	// atomically. Returns ErrStorageNotFound when no matching unused code
	// exists (covers wrong code, reused code, and cross-user mismatch).
	ConsumeRecoveryCode(ctx context.Context, userID ULID, code string, at time.Time) error

	// ---------- v0.7 multi-tenancy + SAML + SCIM ----------
	// All methods below are additive; existing single-tenant deployments
	// never invoke them because the corresponding handlers are mounted
	// only when Config.Organizations / SAML / SCIM are non-nil.

	// Organizations + membership
	InsertOrganization(ctx context.Context, o Organization) (Organization, error)
	OrganizationByID(ctx context.Context, id ULID) (*Organization, error)
	OrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
	UpdateOrganization(ctx context.Context, o Organization) error
	DeleteOrganization(ctx context.Context, id ULID) error

	UpsertOrganizationMember(ctx context.Context, m OrganizationMember) error
	DeleteOrganizationMember(ctx context.Context, orgID, userID ULID) error
	OrganizationMembersByOrg(ctx context.Context, orgID ULID) ([]OrganizationMember, error)
	OrganizationsByUser(ctx context.Context, userID ULID) ([]Organization, error)
	OrganizationMemberRole(ctx context.Context, orgID, userID ULID) (string, error)

	SetSessionActiveOrganization(ctx context.Context, sessionID ULID, orgID *ULID) error

	// SAML connections and identities
	InsertSAMLConnection(ctx context.Context, c SAMLConnection) (SAMLConnection, error)
	UpdateSAMLConnectionRow(ctx context.Context, c SAMLConnection) error
	DeleteSAMLConnection(ctx context.Context, id ULID) error
	SAMLConnectionByID(ctx context.Context, id ULID) (*SAMLConnection, error)
	SAMLConnectionsByOrg(ctx context.Context, orgID ULID) ([]SAMLConnection, error)

	UpsertSAMLIdentity(ctx context.Context, i SAMLIdentity) (SAMLIdentity, error)
	SAMLIdentityByConnectionAndNameID(ctx context.Context, connectionID ULID, nameID string) (*SAMLIdentity, error)
	TouchSAMLIdentityLastLogin(ctx context.Context, id ULID, at time.Time) error

	// SCIM tokens
	InsertSCIMToken(ctx context.Context, t SCIMToken) (SCIMToken, error)
	SCIMTokenByHash(ctx context.Context, hash []byte) (*SCIMToken, error)
	SCIMTokensByOrg(ctx context.Context, orgID ULID) ([]SCIMToken, error)
	RevokeSCIMTokenByID(ctx context.Context, id ULID, at time.Time) error
	TouchSCIMTokenLastUsed(ctx context.Context, id ULID, at time.Time) error

	// SCIM user + group lookups scoped to a single organization
	ListUsersByOrganization(ctx context.Context, orgID ULID, offset, limit int, filter SCIMUserFilter) (users []User, total int, err error)
	ListGroupsByOrganization(ctx context.Context, orgID ULID, offset, limit int, filter SCIMGroupFilter) (groups []Group, total int, err error)
	UserByExternalIDInOrg(ctx context.Context, orgID ULID, externalID string) (*User, error)
	UpdateUserSCIM(ctx context.Context, u User) error

	// Groups (SCIM)
	InsertGroup(ctx context.Context, g Group) (Group, error)
	GroupByID(ctx context.Context, id ULID) (*Group, error)
	GroupByExternalIDInOrg(ctx context.Context, orgID ULID, externalID string) (*Group, error)
	UpdateGroup(ctx context.Context, g Group) error
	DeleteGroup(ctx context.Context, id ULID) error
	SetGroupMembers(ctx context.Context, groupID ULID, userIDs []ULID) error
	AddGroupMembers(ctx context.Context, groupID ULID, userIDs []ULID) error
	RemoveGroupMembers(ctx context.Context, groupID ULID, userIDs []ULID) error
	GroupMembers(ctx context.Context, groupID ULID) ([]ULID, error)

	// ---------- v1.0 RBAC ----------
	// Permissions form a global catalog (no org scope). Insert is idempotent
	// on the name unique index; duplicate names return the existing row
	// rather than an error so seed runs at app start are safe.
	InsertPermission(ctx context.Context, p Permission) (Permission, error)
	PermissionByName(ctx context.Context, name string) (*Permission, error)
	ListPermissions(ctx context.Context) ([]Permission, error)

	InsertRole(ctx context.Context, r Role) (Role, error)
	UpdateRoleRow(ctx context.Context, r Role) (Role, error)
	DeleteRole(ctx context.Context, id ULID) error
	RoleByID(ctx context.Context, id ULID) (*Role, error)
	RoleByOrgAndName(ctx context.Context, orgID *ULID, name string) (*Role, error)
	RolesByOrganization(ctx context.Context, orgID *ULID) ([]Role, error)

	SetRolePermissions(ctx context.Context, roleID ULID, permissionIDs []ULID) error
	// PermissionsByRole returns the permission-name slice for one role.
	// The names are looked up by joining role_permissions to permissions.
	PermissionsByRole(ctx context.Context, roleID ULID) ([]string, error)

	GrantUserRole(ctx context.Context, ur UserRole) error
	RevokeUserRole(ctx context.Context, userID, roleID ULID) error
	RolesForUser(ctx context.Context, userID ULID, orgID *ULID) ([]Role, error)
	PermissionsForUser(ctx context.Context, userID ULID, orgID *ULID) ([]string, error)
	CountUsersWithPermissionInOrg(ctx context.Context, orgID ULID, perm string) (int, error)

	// ---------- v1.0 audit log ----------
	// InsertAuditEvents writes a batch in one round trip. Append-only;
	// adapters MUST NOT expose UPDATE or DELETE for audit rows. Failure
	// returns an error; the writer goroutine logs it and increments
	// Stats.AuditFailed without retrying (documented tradeoff).
	InsertAuditEvents(ctx context.Context, events []AuditEvent) error
	QueryAuditEvents(ctx context.Context, q AuditQuery) (events []AuditEvent, nextCursor string, err error)
}

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
}

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
type RoleSeed struct {
	Name        string
	Description string
	Permissions []string
}

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

	// OAuth (v0.3)
	providers         map[string]Provider
	encryptionKey     []byte
	postLoginRedirect string
	oauthStates       sync.Map // map[string]*oauthState
	oauthStateStop    chan struct{}

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
}

// New validates the Config, applies defaults, and returns a ready TheAuth.
func New(cfg Config) (*TheAuth, error) {
	if cfg.Storage == nil {
		return nil, errors.New("theauth: Config.Storage is required")
	}
	if cfg.BaseURL == "" {
		return nil, errors.New("theauth: Config.BaseURL is required")
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 24 * time.Hour
	}
	if cfg.MagicLinkTTL == 0 {
		cfg.MagicLinkTTL = 15 * time.Minute
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "theauth_session"
	}
	if cfg.EmailSender == nil {
		cfg.EmailSender = email.Noop{}
	}
	if cfg.RateLimitPerIP <= 0 {
		cfg.RateLimitPerIP = 5
	}
	if cfg.RateLimitPerEmail <= 0 {
		cfg.RateLimitPerEmail = 3
	}

	// OAuth validation: any provider configured requires a 32-byte key, and
	// every provider name must be unique within the slice. Empty Providers
	// is fully backward compatible.
	providers := map[string]Provider{}
	if len(cfg.Providers) > 0 {
		if len(cfg.EncryptionKey) != crypto.AESKeyLen {
			return nil, errors.New("theauth: Config.EncryptionKey must be 32 bytes when Providers are configured")
		}
		for _, p := range cfg.Providers {
			if p == nil {
				return nil, errors.New("theauth: Config.Providers contains a nil entry")
			}
			name := p.Name()
			if name == "" {
				return nil, errors.New("theauth: provider returned an empty Name()")
			}
			if _, dup := providers[name]; dup {
				return nil, errors.New("theauth: duplicate provider name: " + name)
			}
			providers[name] = p
		}
	}
	if cfg.PostLoginRedirect == "" {
		cfg.PostLoginRedirect = "/"
	}

	// v0.5: WebAuthn + TOTP validation. Both blocks are optional and
	// orthogonal; consumers can wire either, both, or neither. PR D
	// architecture reorg (2026-06-20): the upstream gowebauthn.WebAuthn
	// instance is constructed inside internal/webauthn.NewService; here we
	// only validate the operator-supplied fields and apply the
	// ChallengeTTL default so the existing handler still reads it for the
	// bridging cookie.
	if cfg.WebAuthn != nil {
		if cfg.WebAuthn.RPID == "" {
			return nil, errors.New("theauth: Config.WebAuthn.RPID is required")
		}
		if len(cfg.WebAuthn.RPOrigins) == 0 {
			return nil, errors.New("theauth: Config.WebAuthn.RPOrigins must have at least one entry")
		}
		if cfg.WebAuthn.ChallengeTTL == 0 {
			cfg.WebAuthn.ChallengeTTL = 5 * time.Minute
		}
	}
	if cfg.TOTP != nil {
		if len(cfg.EncryptionKey) != crypto.AESKeyLen {
			return nil, errors.New("theauth: Config.EncryptionKey must be 32 bytes when TOTP is configured")
		}
		if cfg.TOTP.Issuer == "" {
			return nil, errors.New("theauth: Config.TOTP.Issuer is required")
		}
		if cfg.TOTP.RecoveryCodeCount == 0 {
			cfg.TOTP.RecoveryCodeCount = 10
		}
	}

	// v0.7 validation. SAML and SCIM both require multi-tenancy because the
	// per-connection routing keys off organization ownership.
	if cfg.SCIM != nil && cfg.Organizations == nil {
		return nil, ErrSCIMRequiresOrganizations
	}
	if cfg.SAML != nil && cfg.Organizations == nil {
		return nil, ErrSAMLRequiresOrganizations
	}
	var samlCert *x509.Certificate
	var samlKey *rsa.PrivateKey
	if cfg.SAML != nil {
		if len(cfg.SAML.SPCertificatePEM) == 0 {
			return nil, errors.New("theauth: Config.SAML.SPCertificatePEM is required")
		}
		if len(cfg.SAML.SPPrivateKeyPEM) == 0 {
			return nil, errors.New("theauth: Config.SAML.SPPrivateKeyPEM is required")
		}
		certBlock, _ := pem.Decode(cfg.SAML.SPCertificatePEM)
		if certBlock == nil {
			return nil, errors.New("theauth: Config.SAML.SPCertificatePEM is not valid PEM")
		}
		c, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, errors.New("theauth: Config.SAML.SPCertificatePEM parse: " + err.Error())
		}
		samlCert = c
		keyBlock, _ := pem.Decode(cfg.SAML.SPPrivateKeyPEM)
		if keyBlock == nil {
			return nil, errors.New("theauth: Config.SAML.SPPrivateKeyPEM is not valid PEM")
		}
		// Accept PKCS1 RSA, PKCS8 RSA, and EC-as-PKCS8 (Microsoft tooling
		// often emits PKCS8 even for RSA keys); other key types reject.
		switch keyBlock.Type {
		case "RSA PRIVATE KEY":
			k, kerr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if kerr != nil {
				return nil, errors.New("theauth: Config.SAML.SPPrivateKeyPEM PKCS1 parse: " + kerr.Error())
			}
			samlKey = k
		case "PRIVATE KEY":
			anyKey, kerr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
			if kerr != nil {
				return nil, errors.New("theauth: Config.SAML.SPPrivateKeyPEM PKCS8 parse: " + kerr.Error())
			}
			rk, ok := anyKey.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("theauth: Config.SAML.SPPrivateKeyPEM must be an RSA key")
			}
			samlKey = rk
		default:
			return nil, errors.New("theauth: Config.SAML.SPPrivateKeyPEM unrecognised PEM type: " + keyBlock.Type)
		}
		if cfg.SAML.AuthnRequestTTL == 0 {
			cfg.SAML.AuthnRequestTTL = 10 * time.Minute
		}
		if cfg.SAML.ClockSkew == 0 {
			cfg.SAML.ClockSkew = 30 * time.Second
		}
	}
	if cfg.SCIM != nil {
		if cfg.SCIM.MaxPageSize == 0 {
			cfg.SCIM.MaxPageSize = 200
		}
	}
	// v1.0 RBAC + Admin validation.
	if cfg.Admin != nil && cfg.RBAC == nil {
		return nil, ErrAdminRequiresRBAC
	}
	permCatalog, permIndex, defaultSeeds, err := validateRBAC(cfg.RBAC)
	if err != nil {
		return nil, err
	}

	// v2.0 phase 1 + 2: authorization server validation. Requires a
	// 32-byte EncryptionKey (used to seal JWKS private keys at rest) and
	// a storage adapter satisfying OAuthServerStorage. validateASConfig
	// mutates the struct to apply defaults. PR B architecture reorg
	// (2026-06-20): the actual Service is constructed below after the
	// *TheAuth is allocated so the AgentLookup adapter can close over
	// the back-reference; only the validation happens here.
	if cfg.AuthorizationServer != nil {
		if err := validateASConfig(cfg.AuthorizationServer, cfg.EncryptionKey); err != nil {
			return nil, err
		}
		if _, ok := cfg.Storage.(OAuthServerStorage); !ok {
			return nil, ErrStorageMissingOAuthMethods
		}
	}

	// v2.0 phase 3 + 4: agent identity + delegation policy validation. Only
	// meaningful when an authorization server is configured (the grants land
	// at /oauth/token and the introspection chain walk reads agents and
	// delegation_grants the AS storage owns).
	if cfg.AgentIdentity != nil {
		if cfg.AuthorizationServer == nil {
			return nil, ErrAgentRequiresAS
		}
		if err := validateAgentConfig(cfg.AgentIdentity); err != nil {
			return nil, err
		}
	}
	// v2.0 phase 6: end-user UX requires the agent identity service to be
	// configured (otherwise /account/agents and /account/delegations have
	// no service backing).
	if cfg.AccountUX && cfg.AgentIdentity == nil {
		return nil, ErrAccountUXRequiresAgents
	}

	// security audit H1 (2026-06-20): pre-hash any operator-configured
	// initial access tokens so the plaintext never survives past New.
	// Storage is in-memory only; nothing is written to disk by the
	// library. Operators that rotate tokens out of band must
	// reinstantiate TheAuth.
	var dcrTokenHashes [][32]byte
	if cfg.AuthorizationServer != nil && len(cfg.AuthorizationServer.RegistrationTokens) > 0 {
		dcrTokenHashes = make([][32]byte, 0, len(cfg.AuthorizationServer.RegistrationTokens))
		for _, tok := range cfg.AuthorizationServer.RegistrationTokens {
			trimmed := tok
			if trimmed == "" {
				return nil, errors.New("theauth: AuthorizationServer.RegistrationTokens contains an empty entry")
			}
			dcrTokenHashes = append(dcrTokenHashes, sha256.Sum256([]byte(trimmed)))
		}
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
	}

	// PR D architecture reorg (2026-06-20): wire the audit Service first
	// so subsequent service constructors that take an audit.Emitter
	// receive the live writer (Start spawns the goroutine below). When
	// Config.Audit is nil the rest of the wiring takes audit.NoopEmitter
	// via a.auditEmitter().
	if cfg.Audit != nil {
		a.auditSvc = internalaudit.NewService(cfg.Storage, internalaudit.Config{
			BufferSize:      cfg.Audit.BufferSize,
			BatchSize:       cfg.Audit.BatchSize,
			FlushInterval:   cfg.Audit.FlushInterval,
			CustomRedactor:  internalaudit.Redactor(cfg.Audit.Redactor),
			DefaultRedactor: internalaudit.Redactor(DefaultRedactor),
			DrainTimeout:    cfg.Audit.DrainTimeout,
		})
	}
	// v2.0 phase 1 + 2: wire the extracted authorization server service.
	// PR C architecture reorg (2026-06-20) removes the oauthStorage
	// back-door PR B introduced: the type-asserted OAuthServerStorage view
	// is now passed directly into internal/agent and internal/delegation
	// (which each declare their own minimal Storage interface) and is
	// no longer kept on the root struct. AgentLookup is wired after
	// internal/agent is constructed so the AS introspection / token-
	// exchange paths still resolve "agent:<id>" subjects without
	// importing internal/agent.
	if cfg.AuthorizationServer != nil {
		oss := cfg.Storage.(OAuthServerStorage)
		var policy *internalas.AgentPolicy
		if cfg.AgentIdentity != nil {
			policy = &internalas.AgentPolicy{
				MaxChainDepth:            cfg.AgentIdentity.MaxChainDepth,
				DefaultDelegatedTokenTTL: cfg.AgentIdentity.DefaultDelegatedTokenTTL,
			}
		}
		a.as = internalas.New(internalas.Deps{
			Cfg:           asConfigFromRoot(cfg.AuthorizationServer),
			Storage:       oss,
			EncryptionKey: cfg.EncryptionKey,
			AgentPolicy:   policy,
			Audit:         a,
			// AgentLookup wired below once internal/agent.Service exists.
		})
		// PR C: wire agent + delegation services. The agent service
		// holds the invalidation hook into the AS clientauthcache so a
		// rotated secret takes effect on the next /oauth/token call.
		var agentPolicy *agent.Config
		if cfg.AgentIdentity != nil {
			agentPolicy = &agent.Config{
				MaxChainDepth:            cfg.AgentIdentity.MaxChainDepth,
				MaxDelegationDuration:    cfg.AgentIdentity.MaxDelegationDuration,
				DefaultDelegatedTokenTTL: cfg.AgentIdentity.DefaultDelegatedTokenTTL,
				AgentSecretLength:        cfg.AgentIdentity.AgentSecretLength,
			}
		}
		a.agentSvc = agent.New(oss, agentPolicy, a, a.as.InvalidateClientAuthCache)
		var delegationPolicy *delegation.Config
		if cfg.AgentIdentity != nil {
			delegationPolicy = &delegation.Config{
				MaxDelegationDuration: cfg.AgentIdentity.MaxDelegationDuration,
			}
		}
		a.delegationSvc = delegation.New(oss, delegationPolicy, a.as, a)
		// AS subject-claim lookup is now satisfied by internal/agent. The
		// adapter closes over agentSvc directly so the AS package never
		// imports internal/agent.
		a.as.AgentLookup = internalas.AgentLookupFunc(a.agentSvc.AgentBySubjectClaim)
	}
	// PR A architecture reorg (2026-06): wire the extracted internal
	// services. Each takes a minimal Storage interface satisfied by
	// cfg.Storage via duck typing. The *TheAuth instance itself satisfies
	// audit.Emitter via its EmitAudit method, so the rbac and magiclink
	// services receive a back-reference for audit emission.
	a.sessionSvc = session.New(cfg.Storage, cfg.SessionTTL)
	a.magicSvc = magiclink.New(cfg.Storage, cfg.EmailSender, cfg.BaseURL, cfg.MagicLinkTTL, a.sessionSvc, a)
	a.scimSvc = internalscim.NewService(cfg.Storage, scimConfigFromRoot(cfg.SCIM))
	a.orgsSvc = organizations.New(cfg.Storage, orgsConfigFromRoot(cfg.Organizations))
	a.rbacSvc = rbac.New(cfg.Storage, rbacConfigFromValidated(cfg.RBAC, permCatalog, permIndex, defaultSeeds), a)

	// PR D architecture reorg (2026-06-20): wire the extracted
	// high-complexity services. Each takes a minimal Storage interface
	// satisfied by cfg.Storage via duck typing. The *TheAuth instance
	// satisfies audit.Emitter via EmitAudit so each service receives a
	// back-reference for audit emission. TOTP is constructed before
	// password so the password service can take *totpSvc as the
	// PendingTOTPIssuer; webauthn and saml take the session service so
	// FinishLogin can mint a full session without touching root.
	a.totpSvc = internaltotp.NewService(cfg.Storage, a.sessionSvc, a, totpConfigFromRoot(cfg.TOTP), cfg.EncryptionKey)
	pwSvc, err := password.NewService(cfg.Storage, cfg.EmailSender, a.sessionSvc, a.magicSvc, a.totpSvc, a, password.Config{
		BaseURL:     cfg.BaseURL,
		TOTPEnabled: cfg.TOTP != nil,
	})
	if err != nil {
		return nil, err
	}
	a.passwordSvc = pwSvc
	waSvc, err := internalwebauthn.NewService(cfg.Storage, a.sessionSvc, a, webauthnConfigFromRoot(cfg.WebAuthn))
	if err != nil {
		return nil, err
	}
	a.webauthnSvc = waSvc
	a.samlSvc = internalsaml.NewService(cfg.Storage, a.sessionSvc, a, samlConfigFromRoot(cfg.SAML, samlCert, samlKey))

	if len(providers) > 0 {
		a.oauthStateStop = make(chan struct{})
		go a.oauthStateGCLoop()
	}
	// Start spawns each extracted service's background loops. The audit
	// service spawns the writer goroutine; webauthn / totp / saml spawn
	// their per-service challenge / enrollment / AuthnRequest GC loops.
	// Every "go ..." has a matching Stop path in Close.
	if a.auditSvc != nil {
		if err := a.auditSvc.Start(); err != nil {
			return nil, err
		}
	}
	a.webauthnSvc.Start()
	a.totpSvc.Start()
	a.samlSvc.Start()
	if a.as != nil {
		if err := a.as.Start(context.Background()); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// totpConfigFromRoot translates the root TOTPConfig pointer into the
// internal/totp Config the extracted service consumes. Returns nil when
// the root config is nil so the service's "disabled" branch fires.
func totpConfigFromRoot(c *TOTPConfig) *internaltotp.Config {
	if c == nil {
		return nil
	}
	return &internaltotp.Config{
		Issuer:            c.Issuer,
		RecoveryCodeCount: c.RecoveryCodeCount,
	}
}

// webauthnConfigFromRoot translates the root WebAuthnConfig pointer into
// the internal/webauthn Config the extracted service consumes. Returns
// nil when the root config is nil so the service's "disabled" branch
// fires (every entry point returns "WebAuthn not configured").
func webauthnConfigFromRoot(c *WebAuthnConfig) *internalwebauthn.Config {
	if c == nil {
		return nil
	}
	return &internalwebauthn.Config{
		RPID:          c.RPID,
		RPDisplayName: c.RPDisplayName,
		RPOrigins:     append([]string(nil), c.RPOrigins...),
		ChallengeTTL:  c.ChallengeTTL,
	}
}

// samlConfigFromRoot translates the root SAMLConfig pointer plus the
// pre-parsed cert/key into the internal/saml Config the extracted service
// consumes. Returns nil when the root config is nil so the service's
// "disabled" branch fires.
func samlConfigFromRoot(c *SAMLConfig, cert *x509.Certificate, key *rsa.PrivateKey) *internalsaml.Config {
	if c == nil {
		return nil
	}
	return &internalsaml.Config{
		SPCert:          cert,
		SPKey:           key,
		AuthnRequestTTL: c.AuthnRequestTTL,
		ClockSkew:       c.ClockSkew,
	}
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
	closeOnce := func(ch chan struct{}) {
		if ch == nil {
			return
		}
		select {
		case <-ch:
			// already closed
		default:
			close(ch)
		}
	}
	closeOnce(a.oauthStateStop)
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
		AuditEmitted: c.Emitted,
		AuditWritten: c.Written,
		AuditDropped: c.Dropped,
		AuditFailed:  c.Failed,
	}
}

// scimConfigFromRoot translates the root SCIMConfig pointer into the
// internal/scim Config the extracted service consumes. Returns nil when
// the root config is nil so the service's "disabled" branch fires.
func scimConfigFromRoot(c *SCIMConfig) *internalscim.Config {
	if c == nil {
		return nil
	}
	return &internalscim.Config{RequireHTTPS: c.RequireHTTPS, MaxPageSize: c.MaxPageSize}
}

// orgsConfigFromRoot translates the root OrganizationsConfig pointer into
// the internal/organizations Config. Returns nil when the root config is
// nil so the service's "disabled" branch fires.
func orgsConfigFromRoot(c *OrganizationsConfig) *organizations.Config {
	if c == nil {
		return nil
	}
	return &organizations.Config{}
}

// asConfigFromRoot translates the root AuthorizationServerConfig into
// the internal/as Config the extracted service consumes. The root and
// internal structs intentionally have identical field sets; the
// translation lives here so the internal package does not import root.
// Called once at New() time after validateASConfig has applied defaults.
func asConfigFromRoot(c *AuthorizationServerConfig) internalas.Config {
	if c == nil {
		return internalas.Config{}
	}
	return internalas.Config{
		Issuer:                         c.Issuer,
		Resources:                      append([]ProtectedResource(nil), c.Resources...),
		SigningAlg:                     c.SigningAlg,
		KeyRotationPeriod:              c.KeyRotationPeriod,
		KeyRetention:                   c.KeyRetention,
		AccessTokenTTL:                 c.AccessTokenTTL,
		RefreshTokenTTL:                c.RefreshTokenTTL,
		AuthorizationCodeTTL:           c.AuthorizationCodeTTL,
		RegistrationAccessTokenTTL:     c.RegistrationAccessTokenTTL,
		AllowAnonymousRegistration:     c.AllowAnonymousRegistration,
		RegistrationTokens:             append([]string(nil), c.RegistrationTokens...),
		RegistrationRateLimitPerMinute: c.RegistrationRateLimitPerMinute,
		IntrospectionCacheTTL:          c.IntrospectionCacheTTL,
		LoginURL:                       c.LoginURL,
		DisableRotation:                c.DisableRotation,
		CIMD:                           c.CIMD,
		DPoP:                           dpopConfigFromRoot(c.DPoP),
	}
}

// rbacConfigFromValidated produces the internal/rbac Config from the
// already-validated catalog, index, and default-role seeds. Returns nil
// when the root RBAC config is nil so the service's "disabled" branch
// fires (every method returns models.ErrRBACDisabled, matching the legacy
// root behavior).
func rbacConfigFromValidated(cfg *RBACConfig, catalog []Permission, index map[string]Permission, seeds []RoleSeed) *rbac.Config {
	if cfg == nil {
		return nil
	}
	internalSeeds := make([]rbac.RoleSeed, len(seeds))
	for i, s := range seeds {
		internalSeeds[i] = rbac.RoleSeed{Name: s.Name, Description: s.Description, Permissions: s.Permissions}
	}
	return &rbac.Config{PermCatalog: catalog, PermIndex: index, DefaultRoleSeeds: internalSeeds}
}
