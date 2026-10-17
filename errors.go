package theauth

import (
	"errors"

	"github.com/glincker/theauth-go/v2/internal/models"
	internalsaml "github.com/glincker/theauth-go/v2/internal/saml"
	internaltotp "github.com/glincker/theauth-go/v2/internal/totp"
	internalwebauthn "github.com/glincker/theauth-go/v2/internal/webauthn"
)

// Sentinel errors kept for v0.1 callers that errors.Is-check against them. New code should prefer
// TheAuthError and the Code* constants. Model-layer sentinels are defined in internal/models and
// re-exported here.
var (
	ErrInvalidToken     = models.ErrInvalidToken
	ErrSessionExpired   = models.ErrSessionExpired
	ErrUserNotFound     = errors.New("theauth: user not found")
	ErrMagicLinkExpired = models.ErrMagicLinkExpired
	ErrMagicLinkUsed    = errors.New("theauth: magic link already used")
	ErrEmailNotVerified = errors.New("theauth: email not verified")

	// ErrStorageNotFound is the canonical "row missing" sentinel that storage adapters return on lookup misses.
	ErrStorageNotFound = models.ErrStorageNotFound

	// ErrBadCursor is returned by storage adapters when a keyset pagination cursor fails to decode.
	ErrBadCursor = models.ErrBadCursor

	// ErrReplayDetected is returned by storage when a WebAuthn sign count does not strictly increase.
	// The library treats it as a clone attempt and refuses the login. Authenticators that never count
	// stay at zero and are handled by the caller.
	ErrReplayDetected = internalwebauthn.ErrReplayDetected

	// ErrAlreadyEnrolled is returned when TOTP enrollment finishes for a user who already has a
	// confirmed secret. The user must delete TOTP first to re-enroll.
	ErrAlreadyEnrolled = internaltotp.ErrAlreadyEnrolled

	// ErrSCIMRequiresOrganizations is returned by New when SCIM is set without Organizations, since
	// every SCIM token is bound to one organization.
	ErrSCIMRequiresOrganizations = errors.New("theauth: SCIM requires Organizations to be enabled")
	// ErrSAMLRequiresOrganizations is returned by New when SAML is set without Organizations; routing
	// keys off organization ownership.
	ErrSAMLRequiresOrganizations = errors.New("theauth: SAML requires Organizations to be enabled")
	// ErrSAMLUnsignedAssertion is returned by FinishSAMLLogin when the assertion parses but is not signed.
	ErrSAMLUnsignedAssertion = internalsaml.ErrSAMLUnsignedAssertion
	// ErrSAMLMissingEmail is returned by FinishSAMLLogin when the mapped email attribute is empty.
	ErrSAMLMissingEmail = internalsaml.ErrSAMLMissingEmail
	// ErrSAMLInvalidAssertion wraps the underlying crewjam/saml error for failed signature, condition
	// or replay checks.
	ErrSAMLInvalidAssertion = internalsaml.ErrSAMLInvalidAssertion
	// ErrLastOwner is returned when a member removal would leave the organization with zero owners.
	ErrLastOwner = models.ErrLastOwner
	// ErrUnsupportedFilter is returned by the SCIM filter parser for any shape outside the eq-only whitelist.
	ErrUnsupportedFilter = errors.New("theauth: scim filter not supported")
	// ErrSlugTaken is returned when the organization slug already exists.
	ErrSlugTaken = models.ErrSlugTaken

	// ErrAdminRequiresRBAC is returned by New when Admin is set without RBAC.
	ErrAdminRequiresRBAC = errors.New("theauth: Admin requires RBAC to be enabled")
	// ErrForbidden means the caller lacks a required permission. Handlers map it to 403 "rbac.forbidden".
	ErrForbidden = models.ErrForbidden
	// ErrUnknownPermission means the permission name is not in the catalog. Mapped to 400
	// "rbac.unknown_permission".
	ErrUnknownPermission = models.ErrUnknownPermission
	// ErrRoleInUse means a role delete would leave no user holding "users:admin". Mapped to 409
	// "rbac.role_in_use".
	ErrRoleInUse = models.ErrRoleInUse
	// ErrNoActiveOrg means the session has no active organization. Mapped to 403 "rbac.no_active_org".
	ErrNoActiveOrg = errors.New("theauth: session has no active organization")
	// ErrOrgMismatch means the session's active organization differs from the resource's. Mapped to
	// 403 "rbac.org_mismatch".
	ErrOrgMismatch = errors.New("theauth: session active organization does not match resource")
	// ErrRBACDisabled is returned by RBAC service methods when Config.RBAC is nil.
	ErrRBACDisabled = models.ErrRBACDisabled
)

// Stable error codes callers can switch on. New endpoints return TheAuthError; older ones keep
// returning the sentinels.
const (
	CodeWeakPassword         = models.CodeWeakPassword
	CodeEmailTaken           = models.CodeEmailTaken
	CodeInvalidCredentials   = models.CodeInvalidCredentials
	CodeRateLimited          = models.CodeRateLimited
	CodePasswordResetExpired = models.CodePasswordResetExpired
	CodePasswordResetInvalid = models.CodePasswordResetInvalid

	CodeTOTPRequired    = models.CodeTOTPRequired
	CodeInvalidTOTP     = models.CodeInvalidTOTP
	CodeAlreadyEnrolled = models.CodeAlreadyEnrolled
	CodeWebAuthn        = models.CodeWebAuthn

	CodeIdentityConflict = models.CodeIdentityConflict
	CodeStepUpRequired   = models.CodeStepUpRequired
	CodeLastAuthMethod   = models.CodeLastAuthMethod
)

const (
	// CodePasswordChangeRequired is returned at sign-in when the account must change its password.
	CodePasswordChangeRequired = models.CodePasswordChangeRequired
	// CodeAccountDisabled is returned at sign-in for a disabled account.
	CodeAccountDisabled = models.CodeAccountDisabled
	// CodeReauthRequired means the session needs a recent authentication.
	CodeReauthRequired = models.CodeReauthRequired
	// CodeSessionLimit means the concurrent session cap rejected the sign-in.
	CodeSessionLimit = models.CodeSessionLimit
	// CodeProviderGrantRevoked means the upstream provider rejected the refresh token.
	CodeProviderGrantRevoked = models.CodeProviderGrantRevoked
	// CodeProviderNoRefresh means the stored provider grant cannot be refreshed.
	CodeProviderNoRefresh = models.CodeProviderNoRefresh
)

// TheAuthError is the structured error type returned by service methods. Callers can errors.As it
// and switch on Code.
type TheAuthError = models.TheAuthError

// IdentityConflictError is wrapped inside ErrIdentityConflict when the OAuth account is bound to a
// different user. errors.As it to read ConflictingUserID.
type IdentityConflictError = models.IdentityConflictError

// NewError constructs a TheAuthError with a code, message and optional wrapped cause.
func NewError(code, message string, inner error) *TheAuthError {
	return models.NewError(code, message, inner)
}

var (
	// ErrASRequiresEncryptionKey is returned by New when AuthorizationServer is set without a 32-byte
	// EncryptionKey. The key protects JWKS private keys at rest.
	ErrASRequiresEncryptionKey = models.ErrASRequiresEncryptionKey

	// ErrASIssuerRequired is returned by New when AuthorizationServer is set without an Issuer (RFC 8414).
	ErrASIssuerRequired = models.ErrASIssuerRequired

	// ErrASUnsupportedAlg is returned by New for any signing algorithm other than EdDSA.
	ErrASUnsupportedAlg = models.ErrASUnsupportedAlg

	// ErrOAuthInvalidRequest maps to the OAuth 2.1 "invalid_request" error.
	ErrOAuthInvalidRequest = models.ErrOAuthInvalidRequest

	// ErrOAuthInvalidClient maps to the OAuth 2.1 "invalid_client" error.
	ErrOAuthInvalidClient = models.ErrOAuthInvalidClient

	// ErrOAuthInvalidGrant maps to "invalid_grant": expired or replayed authorization codes and refresh tokens.
	ErrOAuthInvalidGrant = models.ErrOAuthInvalidGrant

	// ErrOAuthInvalidScope maps to the OAuth 2.1 "invalid_scope" error.
	ErrOAuthInvalidScope = models.ErrOAuthInvalidScope

	// ErrOAuthUnsupportedGrantType maps to "unsupported_grant_type".
	ErrOAuthUnsupportedGrantType = models.ErrOAuthUnsupportedGrantType

	// ErrOAuthUnsupportedResponseType maps to "unsupported_response_type".
	ErrOAuthUnsupportedResponseType = models.ErrOAuthUnsupportedResponseType

	ErrOAuthInvalidAuthorizationDetails = models.ErrOAuthInvalidAuthorizationDetails

	// ErrOAuthInvalidResource maps to RFC 8707 "invalid_target".
	ErrOAuthInvalidResource = models.ErrOAuthInvalidResource

	// ErrOAuthRegistrationDenied is returned when DCR has no valid initial access token and
	// AllowAnonymousRegistration is false.
	ErrOAuthRegistrationDenied = models.ErrOAuthRegistrationDenied

	// ErrOAuthRedirectURIMismatch is returned when the token request's redirect_uri differs from the
	// one bound to the code.
	ErrOAuthRedirectURIMismatch = models.ErrOAuthRedirectURIMismatch

	// ErrOAuthPKCEMismatch is returned when code_verifier does not match the stored S256 challenge.
	ErrOAuthPKCEMismatch = models.ErrOAuthPKCEMismatch

	// ErrOAuthAudienceMismatch is returned at introspection when a token's aud does not match the
	// expected resource.
	ErrOAuthAudienceMismatch = models.ErrOAuthAudienceMismatch

	// ErrNotImplemented is returned by paths reserved for a later phase, such as agent credentials of
	// kind x509 or jwk.
	ErrNotImplemented = models.ErrNotImplemented

	// ErrAgentNotFound is returned by lookups whose target agent is absent.
	ErrAgentNotFound = models.ErrAgentNotFound

	// ErrAgentInactive is returned when an operation depends on an agent that is suspended or revoked.
	ErrAgentInactive = models.ErrAgentInactive

	// ErrDelegationNotFound is returned when no delegation grant matches the user, agent and resource.
	// Token exchange surfaces it as access_denied.
	ErrDelegationNotFound = models.ErrDelegationNotFound

	// ErrDelegationRevoked is returned when a delegation grant exists but is revoked. Introspection
	// reports active=false.
	ErrDelegationRevoked = models.ErrDelegationRevoked

	// ErrChainDepthExceeded is returned by token exchange when the actor chain would exceed
	// AgentConfig.MaxChainDepth.
	ErrChainDepthExceeded = models.ErrChainDepthExceeded

	ErrSubjectTokenInvalid = models.ErrSubjectTokenInvalid

	// ErrActorTokenInvalid is returned when actor_token fails signature, issuer, expiry or audience
	// checks, or does not resolve to the authenticated agent client.
	ErrActorTokenInvalid = models.ErrActorTokenInvalid

	// ErrAgentRequiresAS is returned by New when AgentIdentity is set without AuthorizationServer.
	ErrAgentRequiresAS = models.ErrAgentRequiresAS

	ErrAgentChainDepthTooHigh = models.ErrAgentChainDepthTooHigh

	// ErrAccountUXRequiresAgents is returned by New when AccountUX is set without AgentIdentity.
	ErrAccountUXRequiresAgents = models.ErrAccountUXRequiresAgents

	// ErrIdentityConflict is returned when the OAuth account being linked is bound to a different user. errors.As it to
	// *models.IdentityConflictError to read ConflictingUserID.
	ErrIdentityConflict = models.ErrIdentityConflict

	// ErrStepUpRequired is returned by identity-linking methods when the session's AuthLevel is not
	// AuthLevelFull.
	ErrStepUpRequired = models.ErrStepUpRequired

	ErrLastAuthMethod = models.ErrLastAuthMethod

	// ErrCIBAAuthorizationPending is returned by PollBackchannelToken until the user approves or denies.
	ErrCIBAAuthorizationPending = models.ErrCIBAAuthorizationPending

	// ErrCIBASlowDown is returned when the client polls faster than CIBAConfig.MinPollInterval.
	ErrCIBASlowDown = models.ErrCIBASlowDown

	// ErrCIBAAccessDenied is returned when the user denied the request.
	ErrCIBAAccessDenied = models.ErrCIBAAccessDenied

	// ErrCIBAExpiredToken is returned when the auth_req_id has expired.
	ErrCIBAExpiredToken = models.ErrCIBAExpiredToken

	ErrCIBAInvalidRequest = models.ErrCIBAInvalidRequest

	// ErrCIBADisabled is returned when CIBA is not enabled (no CIBA config, or storage lacks CIBAStorage).
	ErrCIBADisabled = models.ErrCIBADisabled

	ErrCIBAUserMismatch = models.ErrCIBAUserMismatch

	ErrDeviceAuthUserCodeTaken = models.ErrDeviceAuthUserCodeTaken

	ErrDeviceUserCodeInvalid = models.ErrDeviceUserCodeInvalid

	ErrDeviceTooManyAttempts = models.ErrDeviceTooManyAttempts

	ErrRegistrationTokenInvalid = models.ErrRegistrationTokenInvalid

	ErrRegistrationTokensDisabled = models.ErrRegistrationTokensDisabled

	ErrDeviceEnrollmentInvalid = models.ErrDeviceEnrollmentInvalid

	ErrDeviceConflict = models.ErrDeviceConflict

	// ErrDevicesDisabled is returned when device tokens are not configured.
	ErrDevicesDisabled = models.ErrDevicesDisabled

	// ErrOIDCDisabled is returned when AuthorizationServer.OIDC is not set.
	ErrOIDCDisabled = models.ErrOIDCDisabled
)

const (
	OAuthErrInvalidRequest          = "invalid_request"
	OAuthErrInvalidClient           = "invalid_client"
	OAuthErrInvalidGrant            = "invalid_grant"
	OAuthErrInvalidScope            = "invalid_scope"
	OAuthErrUnsupportedGrantType    = "unsupported_grant_type"
	OAuthErrUnsupportedResponseType = "unsupported_response_type"
	OAuthErrAccessDenied            = "access_denied"
	OAuthErrServerError             = "server_error"
	OAuthErrInvalidTarget           = "invalid_target"
)

var (
	// ErrCredentialRevoked is returned by a CredentialChecker when the upstream credential a session
	// depends on is no longer valid.
	ErrCredentialRevoked = models.ErrCredentialRevoked

	ErrSessionLinkInvalid = models.ErrSessionLinkInvalid
)

const (
	CodeAccountLocked     = models.CodeAccountLocked
	CodeSignupClosed      = models.CodeSignupClosed
	CodeSetupTokenInvalid = models.CodeSetupTokenInvalid
	CodeBadRequest        = models.CodeBadRequest
	CodeUnauthorized      = models.CodeUnauthorized
	CodeForbidden         = models.CodeForbidden
	CodeNotFound          = models.CodeNotFound
	CodeConflict          = models.CodeConflict
	CodeInternal          = models.CodeInternal
)
