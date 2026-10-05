package theauth

// Type, constant, and function aliases that re-export the v0.x model layer
// (User, Session, MagicLink, organization + SAML + SCIM + RBAC + audit
// structs) from the canonical internal home at
// github.com/glincker/theauth-go/v2/internal/models.
//
// The alias form (type X = models.X, const X = models.X, var X = models.X)
// preserves COMPILE-TIME API stability: every exported symbol in this file
// has the same identity, method set, and signature as the underlying
// internal/models declaration, so downstream consumers cannot tell the
// difference at compile time. This pattern is used by chi
// (go-chi/chi/v5 re-exports middleware), oauth2 (golang.org/x/oauth2
// re-exports endpoint), and go-kit (github.com/go-kit/kit re-exports
// transport types) and is the idiomatic Go answer to "I want the
// package layout I want without breaking the API I shipped."
//
// pkg.go.dev renders alias destinations as links to the underlying type
// docs (in internal/models here, which pkg.go.dev still indexes for the
// docstring even though it is not importable). godoc CLI output renders
// the alias line itself instead of the underlying type body; this is
// expected and is no longer a STABILITY check.

import (
	"context"
	"time"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/cimd"
	"github.com/glincker/theauth-go/v2/internal/models"
	internaloauth "github.com/glincker/theauth-go/v2/internal/oauth"
)

// ---------- v0.x core entity types ----------

// ULID is the canonical ID type, generated in app, stored as uuid in Postgres.
type ULID = models.ULID

type User = models.User

type Session = models.Session

type MagicLink = models.MagicLink

// PasswordResetToken backs the /auth/email-password/forgot+reset flow.
type PasswordResetToken = models.PasswordResetToken

type OAuthAccount = models.OAuthAccount

type WebAuthnCredential = models.WebAuthnCredential

type TOTPSecret = models.TOTPSecret

type RecoveryCode = models.RecoveryCode

// ---------- v0.5 session auth-level constants ----------

const (
	AuthLevelFull       = models.AuthLevelFull
	AuthLevelPending2FA = models.AuthLevelPending2FA
)

// ---------- v0.7 multi-tenancy + SAML + SCIM ----------

const (
	OrgRoleOwner  = models.OrgRoleOwner
	OrgRoleAdmin  = models.OrgRoleAdmin
	OrgRoleMember = models.OrgRoleMember
)

type Organization = models.Organization

type OrganizationMember = models.OrganizationMember

type SAMLAttributeMap = models.SAMLAttributeMap

// DefaultSAMLAttributeMap returns the WS-Federation claim URIs that
// Microsoft, Okta, and OneLogin emit by default.
var DefaultSAMLAttributeMap = models.DefaultSAMLAttributeMap

type SAMLConnection = models.SAMLConnection

type SAMLIdentity = models.SAMLIdentity

type SCIMToken = models.SCIMToken

type Group = models.Group

type SCIMUserFilter = models.SCIMUserFilter

type SCIMGroupFilter = models.SCIMGroupFilter

// ---------- v1.0 RBAC + audit ----------

type Permission = models.Permission

type Role = models.Role

type UserRole = models.UserRole

// SystemRoleSuperAdmin is the global role whose presence on a user bypasses
// every permission check.
const SystemRoleSuperAdmin = models.SystemRoleSuperAdmin

type TargetRef = models.TargetRef

type AuditEvent = models.AuditEvent

type AuditQuery = models.AuditQuery

type Stats = models.Stats

// ---------- v2.0 OAuth 2.1 AS primitives (merged from models_v20.go in PR G) ----------

type ClientOwner = models.ClientOwner

type OAuthClient = models.OAuthClient

type AuthorizationCode = models.AuthorizationCode

type RefreshToken = models.RefreshToken

type JWKSKey = models.JWKSKey

// JWKS key state constants.
const (
	JWKSStateNext     = models.JWKSStateNext
	JWKSStateCurrent  = models.JWKSStateCurrent
	JWKSStatePrevious = models.JWKSStatePrevious
	JWKSStateRetired  = models.JWKSStateRetired
)

// Client owner kind constants persisted in oauth_clients.owner_kind.
const (
	ClientOwnerKindUser         = models.ClientOwnerKindUser
	ClientOwnerKindOrganization = models.ClientOwnerKindOrganization
	ClientOwnerKindAgent        = models.ClientOwnerKindAgent
	ClientOwnerKindAnonymous    = models.ClientOwnerKindAnonymous
)

// Client authentication method constants.
const (
	ClientAuthSecretBasic = models.ClientAuthSecretBasic
	ClientAuthSecretPost  = models.ClientAuthSecretPost
	ClientAuthNone        = models.ClientAuthNone
)

// Grant type constants.
const (
	GrantTypeAuthorizationCode = models.GrantTypeAuthorizationCode
	GrantTypeRefreshToken      = models.GrantTypeRefreshToken
	GrantTypeClientCredentials = models.GrantTypeClientCredentials
	GrantTypeTokenExchange     = models.GrantTypeTokenExchange
)

// Token type URNs used by the RFC 8693 token-exchange grant.
const (
	TokenTypeAccessToken = models.TokenTypeAccessToken
)

// Response type constants. OAuth 2.1 supports only "code".
const (
	ResponseTypeCode = models.ResponseTypeCode
)

// ---------- v2.0 phase 3 agent identity ----------

type AgentOwner = models.AgentOwner

type CreateAgentInput = models.CreateAgentInput

// Agent lifecycle status values persisted in agents.status.
const (
	AgentStatusActive    = models.AgentStatusActive
	AgentStatusSuspended = models.AgentStatusSuspended
	AgentStatusRevoked   = models.AgentStatusRevoked
)

// Agent credential kind constants persisted in agent_credentials.kind.
const (
	AgentCredentialKindSecret = models.AgentCredentialKindSecret
	AgentCredentialKindX509   = models.AgentCredentialKindX509
	AgentCredentialKindJWK    = models.AgentCredentialKindJWK
)

// AgentSubjectPrefix is prepended to an agent ID inside JWT sub and act.sub
// claims so resource servers can distinguish a user subject from an agent
// subject without consulting storage.
const AgentSubjectPrefix = models.AgentSubjectPrefix

type Agent = models.Agent

type AgentCredential = models.AgentCredential

type AgentSecret = models.AgentSecret

// ---------- v2.0 phase 4 delegation ----------

type DelegationGrant = models.DelegationGrant

type GrantDelegationInput = models.GrantDelegationInput

type ActorClaim = models.ActorClaim

// ---------- v2.0 resource + DCR types ----------

// ProtectedResource describes one resource server protected by this AS.
type ProtectedResource = models.ProtectedResource

// RegisteredClient is the JSON body returned on a successful registration
// (RFC 7591 section 3.2.1).
type RegisteredClient = models.RegisteredClient

// ---------- CIBA (RFC 9509) types ----------

// BackchannelRequest is the persistent record for one CIBA flow.
type BackchannelRequest = models.BackchannelRequest

// CIBA status constants.
const (
	BackchannelStatusPending  = models.BackchannelStatusPending
	BackchannelStatusApproved = models.BackchannelStatusApproved
	BackchannelStatusDenied   = models.BackchannelStatusDenied
)

// GrantTypeCIBA is the CIBA grant type URN per RFC 9509.
const GrantTypeCIBA = models.GrantTypeCIBA

// ---------- Lifecycle hook enums (v2.5) ----------

// SignupMethod identifies which credential path created a user. Passed to
// LifecycleHooks.OnSignup so consumers can branch tenant-provisioning,
// welcome-email, or analytics by the path the user came in on.
type SignupMethod string

const (
	SignupMethodPassword  SignupMethod = "password"
	SignupMethodMagicLink SignupMethod = "magic_link"
	SignupMethodOAuth     SignupMethod = "oauth"
	SignupMethodPasskey   SignupMethod = "passkey"
	SignupMethodSAML      SignupMethod = "saml"
)

// MFAKind identifies which second factor a user just enabled. Passed to
// LifecycleHooks.OnMFAEnabled.
type MFAKind string

const (
	MFAKindTOTP          MFAKind = "totp"
	MFAKindWebAuthn      MFAKind = "webauthn"
	MFAKindRecoveryCodes MFAKind = "recovery_codes"
)

// ---------- Request context keys ----------

type ctxKey int

const (
	userKey ctxKey = iota
	sessionKey
)

// UserFromContext returns the authenticated User attached by Authn middleware,
// if any. Returns false when the request is anonymous.
func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userKey).(*User)
	return u, ok
}

// SessionFromContext returns the Session attached by Authn middleware,
// if any. Returns false when the request is anonymous.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionKey).(*Session)
	return s, ok
}

// ---------- OAuth provider type aliases ----------

// Provider is the contract every OAuth 2.0 / OIDC provider implements. Each
// concrete provider lives in its own sub-package under provider/<name>/ so
// consumers can pick what to import (avoids dragging in HTTP clients for
// providers they will never use).
//
// The type moved to internal/oauth in PR H (2026-06-22); this alias keeps
// the v0.3+ public surface byte-stable.
type Provider = internaloauth.Provider

// ProviderResolver supplies OAuth/OIDC providers at request time. Resolve
// returns (nil, false, nil) for an unknown name and an error when the lookup
// itself failed. The returned provider's Name() must equal name.
type ProviderResolver = internaloauth.ProviderResolver

// ProviderLister is optionally implemented by a ProviderResolver so
// ListProviders can include its providers.
type ProviderLister = internaloauth.ProviderLister

// NonceProvider is the optional Provider extension for OIDC providers that
// validate an ID token nonce. The OAuth service detects it automatically.
type NonceProvider = internaloauth.NonceProvider

// ProviderToken is the normalized shape of an OAuth token exchange response.
// Providers vary in which fields they populate (e.g. GitHub typically omits
// RefreshToken and ExpiresAt for "no-expiry" tokens). Storage encrypts the
// access/refresh tokens at rest via crypto.Encrypt.
//
// The type moved to internal/oauth in PR H (2026-06-22); this alias keeps
// the v0.3+ public surface byte-stable.
type ProviderToken = internaloauth.ProviderToken

// ProviderUser is the normalized shape of a provider's userinfo response.
// ID is the provider-stable user identifier (e.g. GitHub numeric id as a
// string) and is what oauth_accounts.provider_user_id stores. Email may be
// empty when the user denied the email scope or has no public email on the
// provider; EmailVerified is true only when the provider attests to it.
//
// The type moved to internal/oauth in PR H (2026-06-22); this alias keeps
// the v0.3+ public surface byte-stable.
type ProviderUser = internaloauth.ProviderUser

// ---------- JWKS rotation surface ----------

// jwks.go: thin forwarders for the JWKS rotation surface. PR B
// architecture reorg (2026-06-20) moved the JWKS state machine and the
// Ed25519 keypair lifecycle into internal/as. PR G (2026-06-21) removed
// the unexported currentSigningKey / publicKeyByKID helpers because every
// in-tree caller now goes through *as.Service directly (the AS handler
// package, the v2 token services, and the JWT verify middleware all
// import internal/as). Only the operator-facing RotateSigningKey method
// remains on the root receiver because it is part of the v2.0 public API.

// RotateSigningKey advances the JWKS state machine one step: previous
// (if any) is retired, current becomes previous, next becomes current,
// and a fresh next is minted. Idempotent under concurrent callers (each
// call mints one fresh next). Operators can invoke this on emergency
// without waiting for the scheduled tick.
func (a *TheAuth) RotateSigningKey(ctx context.Context) error {
	return a.as.RotateSigningKey(ctx)
}

// ---------- CIMD (Client ID Metadata Documents) ----------

// cimd.go: public CIMD (Client ID Metadata Documents) surface, per the
// MCP authorization specification 2025-11-25.
//
// CIMD lets an OAuth client publish its RFC 7591 client metadata at a
// stable https URL whose value IS the client_id. The AS fetches the
// URL, validates the document, and uses the metadata in place of a
// locally stored DCR registration. The MCP spec demoted RFC 7591 DCR
// (still supported) in favor of CIMD as the preferred client
// identification mechanism because CIMD eliminates the server-side
// registration step entirely.
//
// Wire CIMD on Config.AuthorizationServer.CIMD; the field is optional
// and additive. When nil, theauth-go behaves exactly as it did pre-CIMD
// (every client_id consults OAuthServerStorage).

// CIMDConfig wires the CIMD service onto the AS. Set on
// AuthorizationServerConfig.CIMD to enable https-URL client_id
// resolution. Defaults to DenyAll (fail-closed); operators must opt in
// to a permissive policy explicitly.
//
// Aliased from internal/cimd so consumers can wire CIMDConfig{...} at
// the public surface without importing the internal package.
type CIMDConfig = cimd.Config

// CIMDTrustPolicy decides which https client_id URLs the AS is allowed
// to fetch as CIMD documents. Aliased from internal/cimd.TrustPolicy.
type CIMDTrustPolicy = cimd.TrustPolicy

// DenyAll returns a CIMDTrustPolicy that rejects every URL. This is the
// fail-closed default applied when CIMDConfig.TrustPolicy is nil and is
// the default returned here so operator code reads naturally:
//
//	cfg.AuthorizationServer.CIMD = &theauth.CIMDConfig{
//	    TrustPolicy: theauth.DenyAll(), // explicit acknowledgement
//	}
//
// DenyAll mirrors the security audit H4 default for TrustedProxies:
// trust must be explicit, never implicit.
func DenyAll() CIMDTrustPolicy { return cimd.DenyAll() }

// AllowAnyHTTPS returns a CIMDTrustPolicy that permits every absolute
// https URL. Use only in deployments that intentionally federate with
// the open MCP ecosystem; production deployments that know their
// clients ahead of time should prefer AllowHTTPSHost.
func AllowAnyHTTPS() CIMDTrustPolicy { return cimd.AllowAnyHTTPS() }

// AllowHTTPSHost returns a CIMDTrustPolicy that permits one specific
// host (case-insensitive, exact match).
func AllowHTTPSHost(host string) CIMDTrustPolicy { return cimd.AllowHTTPSHost(host) }

// AllowHTTPSHosts returns a CIMDTrustPolicy that permits any of the
// supplied hosts (case-insensitive, exact match). An empty list
// produces a permanently-deny policy so a typo cannot silently allow
// every host.
func AllowHTTPSHosts(hosts ...string) CIMDTrustPolicy { return cimd.AllowHTTPSHosts(hosts...) }

// ---------- CIBA (RFC 9509 backchannel authentication) ----------

// ciba.go: root-package CIBA surface.
// CIBAConfig, AuthenticationDevice, CIBANotification are thin wrappers
// that re-export the internal/as counterparts so operators only import the
// root package. ApproveBackchannelAuth / DenyBackchannelAuth are the two
// operator-facing service methods.

// AuthenticationDevice is the operator-supplied interface that bridges the
// AS to the actual push delivery mechanism (FCM, APNs, SMS, etc.). See
// internal/as.AuthenticationDevice for the full contract.
type AuthenticationDevice interface {
	Notify(ctx context.Context, req CIBANotification) error
}

// CIBANotification is the payload delivered to AuthenticationDevice.Notify.
type CIBANotification struct {
	AuthReqID      string
	UserID         string
	ClientID       string
	Scopes         []string
	BindingMessage string
	ExpiresAt      time.Time
}

// NoopAuthenticationDevice satisfies AuthenticationDevice by discarding every
// notification. Suitable for unit tests and operator deployments that manage
// notifications out of band.
type NoopAuthenticationDevice struct{}

// Notify satisfies AuthenticationDevice. It is a no-op and always returns nil.
func (NoopAuthenticationDevice) Notify(_ context.Context, _ CIBANotification) error { return nil }

// LoggingAuthenticationDevice satisfies AuthenticationDevice by logging
// notifications to log/slog at INFO level. Suitable for staging environments.
type LoggingAuthenticationDevice struct{}

// Notify satisfies AuthenticationDevice. It logs the notification details and
// returns nil.
func (LoggingAuthenticationDevice) Notify(_ context.Context, req CIBANotification) error {
	// Fields are accessible on req; no-op here keeps the root package
	// dependency-light. Operators can replace this with a real slog call.
	_ = req
	return nil
}

// CIBAConfig wires the CIBA feature on the authorization server.
// Set Config.AuthorizationServer.CIBA to enable. Leave nil (default) to
// disable CIBA entirely.
type CIBAConfig struct {
	// AuthenticationDevice is required. The AS calls Notify on every
	// POST /oauth/bc-authorize so the user's device receives the push.
	AuthenticationDevice AuthenticationDevice

	// DefaultExpiry is the default auth_req_id lifetime. Defaults to 300s.
	DefaultExpiry time.Duration

	// DefaultInterval is the default client poll interval. Defaults to 5s.
	DefaultInterval time.Duration

	// MaxRequestedExpiry caps the requested_expiry parameter. Defaults to 600s.
	MaxRequestedExpiry time.Duration

	// MinPollInterval is the floor that triggers slow_down when breached.
	// Defaults to 3s.
	MinPollInterval time.Duration
}

// cibaAdapterDevice bridges the root AuthenticationDevice to the internal
// internalas.AuthenticationDevice interface. Both use context.Context so the
// adapter is a thin forwarder.
type cibaAdapterDevice struct {
	root AuthenticationDevice
}

func (a cibaAdapterDevice) Notify(ctx context.Context, req internalas.CIBANotification) error {
	return a.root.Notify(ctx, CIBANotification{
		AuthReqID:      req.AuthReqID,
		UserID:         req.UserID,
		ClientID:       req.ClientID,
		Scopes:         append([]string(nil), req.Scopes...),
		BindingMessage: req.BindingMessage,
		ExpiresAt:      req.ExpiresAt,
	})
}

// cibaConfigToInternal converts a root CIBAConfig to the internal/as version.
// Returns nil when cfg is nil so callers can nil-check.
func cibaConfigToInternal(cfg *CIBAConfig) *internalas.CIBAConfig {
	if cfg == nil {
		return nil
	}
	var device internalas.AuthenticationDevice
	if cfg.AuthenticationDevice != nil {
		device = cibaAdapterDevice{root: cfg.AuthenticationDevice}
	}
	return &internalas.CIBAConfig{
		AuthenticationDevice: device,
		DefaultExpiry:        cfg.DefaultExpiry,
		DefaultInterval:      cfg.DefaultInterval,
		MaxRequestedExpiry:   cfg.MaxRequestedExpiry,
		MinPollInterval:      cfg.MinPollInterval,
	}
}

// ApproveBackchannelAuth marks the pending CIBA request as approved and
// provisions the access + refresh tokens that the next poll will return.
//
// userID MUST be the resolved identity of the authenticating user. When the
// original request supplied a login_hint that the operator resolved to this
// user, pass the matching ULID. If the request was already bound to a
// different user, ApproveBackchannelAuth returns ErrCIBAUserMismatch.
//
// Returns ErrCIBADisabled when CIBA is not configured or the storage does not
// implement CIBAStorage.
func (a *TheAuth) ApproveBackchannelAuth(ctx context.Context, authReqID string, userID ULID) error {
	if a.as == nil {
		return models.ErrCIBADisabled
	}
	return a.as.ApproveBackchannelRequest(ctx, authReqID, userID)
}

// DenyBackchannelAuth marks the pending CIBA request as denied. The next
// client poll returns access_denied.
//
// Returns ErrCIBADisabled when CIBA is not configured.
func (a *TheAuth) DenyBackchannelAuth(ctx context.Context, authReqID string, userID ULID) error {
	if a.as == nil {
		return models.ErrCIBADisabled
	}
	return a.as.DenyBackchannelRequest(ctx, authReqID, userID)
}
