package theauth

// Type, constant and function aliases that re-export the model layer from internal/models. Aliases
// keep the public symbols identical in identity, method set and signature, so downstream consumers
// see no compile-time change.

import (
	"context"
	"time"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/cimd"
	"github.com/glincker/theauth-go/v2/internal/models"
	internaloauth "github.com/glincker/theauth-go/v2/internal/oauth"
)

// ULID is the canonical ID type, generated in the app and stored as uuid in Postgres.
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

const (
	AuthLevelFull       = models.AuthLevelFull
	AuthLevelPending2FA = models.AuthLevelPending2FA
)

const (
	AMRPassword     = models.AMRPassword
	AMROTP          = models.AMROTP
	AMRHardwareKey  = models.AMRHardwareKey
	AMRSoftwareKey  = models.AMRSoftwareKey
	AMRUserVerified = models.AMRUserVerified
	AMRMFA          = models.AMRMFA
	AMREmail        = models.AMREmail
	AMRFederated    = models.AMRFederated
	AMRSSO          = models.AMRSSO
)

// MergeAuthMethods appends the methods in add that existing lacks (lowercased, order kept).
func MergeAuthMethods(existing []string, add ...string) []string {
	return models.MergeAuthMethods(existing, add...)
}

const (
	OrgRoleOwner  = models.OrgRoleOwner
	OrgRoleAdmin  = models.OrgRoleAdmin
	OrgRoleMember = models.OrgRoleMember
)

type Organization = models.Organization

type OrganizationMember = models.OrganizationMember

type SAMLAttributeMap = models.SAMLAttributeMap

// DefaultSAMLAttributeMap returns the WS-Federation claim URIs that Microsoft, Okta and OneLogin
// emit by default.
var DefaultSAMLAttributeMap = models.DefaultSAMLAttributeMap

type SAMLConnection = models.SAMLConnection

type SAMLIdentity = models.SAMLIdentity

type SCIMToken = models.SCIMToken

type Group = models.Group

type SCIMUserFilter = models.SCIMUserFilter

type SCIMGroupFilter = models.SCIMGroupFilter

type Permission = models.Permission

type Role = models.Role

type UserRole = models.UserRole

// SystemRoleSuperAdmin is the global role whose presence on a user bypasses every permission check.
const SystemRoleSuperAdmin = models.SystemRoleSuperAdmin

type TargetRef = models.TargetRef

type AuditEvent = models.AuditEvent

type AuditQuery = models.AuditQuery

// AuditProvenanceFilter is AuditQuery.Provenance.
type AuditProvenanceFilter = models.ProvenanceFilter

// Audit read orders for AuditQuery.Order.
const (
	AuditOrderAsc  = models.AuditOrderAsc
	AuditOrderDesc = models.AuditOrderDesc
)

type Stats = models.Stats

type ClientOwner = models.ClientOwner

type OAuthClient = models.OAuthClient

type AuthorizationCode = models.AuthorizationCode

type RefreshToken = models.RefreshToken

type JWKSKey = models.JWKSKey

const (
	JWKSStateNext     = models.JWKSStateNext
	JWKSStateCurrent  = models.JWKSStateCurrent
	JWKSStatePrevious = models.JWKSStatePrevious
	JWKSStateRetired  = models.JWKSStateRetired
)

const (
	ClientOwnerKindUser         = models.ClientOwnerKindUser
	ClientOwnerKindOrganization = models.ClientOwnerKindOrganization
	ClientOwnerKindAgent        = models.ClientOwnerKindAgent
	ClientOwnerKindAnonymous    = models.ClientOwnerKindAnonymous
)

const (
	ClientAuthSecretBasic = models.ClientAuthSecretBasic
	ClientAuthSecretPost  = models.ClientAuthSecretPost
	ClientAuthNone        = models.ClientAuthNone
)

const (
	GrantTypeAuthorizationCode = models.GrantTypeAuthorizationCode
	GrantTypeRefreshToken      = models.GrantTypeRefreshToken
	GrantTypeClientCredentials = models.GrantTypeClientCredentials
	GrantTypeTokenExchange     = models.GrantTypeTokenExchange
)

const (
	TokenTypeAccessToken = models.TokenTypeAccessToken
)

const (
	ResponseTypeCode = models.ResponseTypeCode
)

type AgentOwner = models.AgentOwner

type CreateAgentInput = models.CreateAgentInput

const (
	AgentStatusActive    = models.AgentStatusActive
	AgentStatusSuspended = models.AgentStatusSuspended
	AgentStatusRevoked   = models.AgentStatusRevoked
)

const (
	AgentCredentialKindSecret = models.AgentCredentialKindSecret
	AgentCredentialKindX509   = models.AgentCredentialKindX509
	AgentCredentialKindJWK    = models.AgentCredentialKindJWK
)

// AgentSubjectPrefix is prepended to an agent ID in JWT sub and act.sub claims, so resource servers
// can tell agents from users without consulting storage.
const AgentSubjectPrefix = models.AgentSubjectPrefix

type Agent = models.Agent

type AgentCredential = models.AgentCredential

type AgentSecret = models.AgentSecret

type DelegationGrant = models.DelegationGrant

type GrantDelegationInput = models.GrantDelegationInput

type ActorClaim = models.ActorClaim

// ProtectedResource describes one resource server protected by this AS.
type ProtectedResource = models.ProtectedResource

// RegisteredClient is the JSON body returned on a successful registration (RFC 7591 section 3.2.1).
type RegisteredClient = models.RegisteredClient

// BackchannelRequest is the persistent record for one CIBA flow.
type BackchannelRequest = models.BackchannelRequest

const (
	BackchannelStatusPending  = models.BackchannelStatusPending
	BackchannelStatusApproved = models.BackchannelStatusApproved
	BackchannelStatusDenied   = models.BackchannelStatusDenied
)

// GrantTypeCIBA is the CIBA grant type URN per RFC 9509.
const GrantTypeCIBA = models.GrantTypeCIBA

// OpaqueAccessToken is the server-side record behind a reference access token. Only its SHA-256
// hash is stored.
type OpaqueAccessToken = models.OpaqueAccessToken

const (
	AccessTokenFormatJWT    = models.AccessTokenFormatJWT
	AccessTokenFormatOpaque = models.AccessTokenFormatOpaque
)

const (
	SubjectTypePublic   = models.SubjectTypePublic
	SubjectTypePairwise = models.SubjectTypePairwise
)

// TokenTypeIDJAG is the token type URN of an Identity Assertion JWT Authorization Grant.
const TokenTypeIDJAG = models.TokenTypeIDJAG

// DeviceAuthorization is the record of one OAuth device flow at /oauth/device_authorization. It is
// unrelated to DeviceCode, which belongs to the API-token device flow.
type DeviceAuthorization = models.DeviceAuthorization

const (
	DeviceAuthPending  = models.DeviceAuthPending
	DeviceAuthApproved = models.DeviceAuthApproved
	DeviceAuthDenied   = models.DeviceAuthDenied
	DeviceAuthConsumed = models.DeviceAuthConsumed
)

// GrantTypeDeviceCode is the RFC 8628 grant type URN.
const GrantTypeDeviceCode = models.GrantTypeDeviceCode

// Device is a registered constrained device (see DeviceTokensConfig).
type Device = models.Device

// DeviceAttestationJoinToken is the attestation kind of a device enrolled with a join token.
const DeviceAttestationJoinToken = models.DeviceAttestationJoinToken

// DeviceJoinToken is a single-use device enrollment token.
type DeviceJoinToken = models.DeviceJoinToken

const (
	DeviceStatusActive  = models.DeviceStatusActive
	DeviceStatusRevoked = models.DeviceStatusRevoked
)

// RegistrationToken is an initial access token for POST /oauth/register.
type RegistrationToken = models.RegistrationToken

// SignupMethod identifies which credential path created a user. LifecycleHooks.OnSignup receives it
// so consumers can branch on the path.
type SignupMethod string

const (
	SignupMethodPassword  SignupMethod = "password"
	SignupMethodMagicLink SignupMethod = "magic_link"
	SignupMethodOAuth     SignupMethod = "oauth"
	SignupMethodPasskey   SignupMethod = "passkey"
	SignupMethodSAML      SignupMethod = "saml"
)

// MFAKind identifies which second factor a user just enabled. Passed to LifecycleHooks.OnMFAEnabled.
type MFAKind string

const (
	MFAKindTOTP          MFAKind = "totp"
	MFAKindWebAuthn      MFAKind = "webauthn"
	MFAKindRecoveryCodes MFAKind = "recovery_codes"
)

type ctxKey int

const (
	userKey ctxKey = iota
	sessionKey
)

// UserFromContext returns the user attached by Authn middleware, or false for anonymous requests.
func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userKey).(*User)
	return u, ok
}

// SessionFromContext returns the session attached by Authn middleware, or false for anonymous requests.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionKey).(*Session)
	return s, ok
}

// Provider is the contract every OAuth 2.0 and OIDC provider implements. Each provider lives in its
// own sub-package under provider/<name>/ so consumers import only what they use.
type Provider = internaloauth.Provider

// ProviderResolver supplies providers at request time. Resolve returns (nil, false, nil) for an
// unknown name and an error when the lookup itself failed.
type ProviderResolver = internaloauth.ProviderResolver

// ProviderLister is optionally implemented by a ProviderResolver so ListProviders can include its
// providers.
type ProviderLister = internaloauth.ProviderLister

// NonceProvider is the optional Provider extension for OIDC providers that validate an ID token nonce.
type NonceProvider = internaloauth.NonceProvider

// ProviderToken is the normalized shape of an OAuth token exchange response. Providers vary in
// which fields they fill (GitHub often omits RefreshToken and ExpiresAt). Storage encrypts the
// tokens at rest.
type ProviderToken = internaloauth.ProviderToken

// ProviderUser is the normalized shape of a provider's userinfo response. ID is the provider-stable
// identifier stored as oauth_accounts.provider_user_id. EmailVerified is true only when the
// provider attests to it.
type ProviderUser = internaloauth.ProviderUser

// RotateSigningKey advances the JWKS state machine one step. Each call mints a fresh next key, so
// concurrent calls are safe.
func (a *TheAuth) RotateSigningKey(ctx context.Context) error {
	return a.as.RotateSigningKey(ctx)
}

// CIMD lets a client publish its metadata at an https
// URL that is also its client_id, replacing server-side DCR. It is optional: nil keeps the pre-CIMD behavior.

// CIMDConfig wires the CIMD service onto the AS. The default trust policy is DenyAll (fail-closed).
type CIMDConfig = cimd.Config

// CIMDTrustPolicy decides which https client_id URLs the AS may fetch as CIMD documents.
type CIMDTrustPolicy = cimd.TrustPolicy

// DenyAll returns a CIMDTrustPolicy that rejects every URL. It is the fail-closed default: trust
// must be explicit.
func DenyAll() CIMDTrustPolicy { return cimd.DenyAll() }

// AllowAnyHTTPS permits every absolute https URL. Use it only when federating with the open MCP
// ecosystem; known clients should prefer AllowHTTPSHost.
func AllowAnyHTTPS() CIMDTrustPolicy { return cimd.AllowAnyHTTPS() }

// AllowHTTPSHost permits one host (case-insensitive, exact match).
func AllowHTTPSHost(host string) CIMDTrustPolicy { return cimd.AllowHTTPSHost(host) }

// AllowHTTPSHosts permits any of the hosts (case-insensitive, exact match). An empty list denies
// everything, so a typo cannot silently allow every host.
func AllowHTTPSHosts(hosts ...string) CIMDTrustPolicy { return cimd.AllowHTTPSHosts(hosts...) }

// AuthenticationDevice bridges the AS to a push delivery mechanism (FCM, APNs, SMS). See
// internal/as.AuthenticationDevice.
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

// NoopAuthenticationDevice discards every notification. Suitable for tests and out-of-band
// notification setups.
type NoopAuthenticationDevice struct{}

func (NoopAuthenticationDevice) Notify(_ context.Context, _ CIBANotification) error { return nil }

// LoggingAuthenticationDevice logs notifications at INFO. Suitable for staging.
type LoggingAuthenticationDevice struct{}

func (LoggingAuthenticationDevice) Notify(_ context.Context, req CIBANotification) error {
	_ = req
	return nil
}

// CIBAConfig wires CIBA on the authorization server. Leave nil (the default) to disable it.
type CIBAConfig struct {
	// AuthenticationDevice is required; the AS calls Notify on every POST /oauth/bc-authorize.
	AuthenticationDevice AuthenticationDevice

	DefaultExpiry time.Duration

	DefaultInterval time.Duration

	MaxRequestedExpiry time.Duration

	MinPollInterval time.Duration
}

// cibaAdapterDevice forwards the root AuthenticationDevice to the internal/as interface.
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

// ApproveBackchannelAuth marks the pending CIBA request approved and provisions the tokens the next
// poll returns. userID must be the authenticating user; a request already bound to another user
// returns ErrCIBAUserMismatch.
func (a *TheAuth) ApproveBackchannelAuth(ctx context.Context, authReqID string, userID ULID) error {
	if a.as == nil {
		return models.ErrCIBADisabled
	}
	return a.as.ApproveBackchannelRequest(ctx, authReqID, userID)
}

// DenyBackchannelAuth marks the pending CIBA request denied; the next poll returns access_denied.
func (a *TheAuth) DenyBackchannelAuth(ctx context.Context, authReqID string, userID ULID) error {
	if a.as == nil {
		return models.ErrCIBADisabled
	}
	return a.as.DenyBackchannelRequest(ctx, authReqID, userID)
}
