package theauth

import (
	"context"
	"time"
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
// Wiring status (v2.5):
//   - OnSignup, OnSignin: wired at email + password.
//   - OnPasswordChange, OnMFAEnabled, OnTokenIssued, OnOrgSwitch: reserved.
//     Wiring lands incrementally in v2.5.x without API change.
type LifecycleHooks struct {
	OnSignup         func(ctx context.Context, user *User, method SignupMethod) error
	OnSignin         func(ctx context.Context, user *User, sess *Session) error
	OnPasswordChange func(ctx context.Context, user *User) error
	OnMFAEnabled     func(ctx context.Context, user *User, kind MFAKind) error
	OnTokenIssued    func(ctx context.Context, claims map[string]any) (map[string]any, error)
	OnOrgSwitch      func(ctx context.Context, user *User, orgID string) error
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
