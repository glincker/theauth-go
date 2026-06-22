package theauth

import (
	"errors"

	"github.com/glincker/theauth-go/internal/models"
	internalsaml "github.com/glincker/theauth-go/internal/saml"
	internaltotp "github.com/glincker/theauth-go/internal/totp"
	internalwebauthn "github.com/glincker/theauth-go/internal/webauthn"
)

// Sentinel errors retained for backward compatibility with v0.1 callers
// that errors.Is-check against them. New code should prefer TheAuthError +
// the Code* constants below.
//
// Model-layer sentinels (storage misses, expiry states, RBAC catalog
// rejections, organization invariants) are defined in internal/models and
// re-exported here via var aliases. Service-flow and admin precondition
// sentinels remain defined locally.
var (
	ErrInvalidToken     = models.ErrInvalidToken
	ErrSessionExpired   = models.ErrSessionExpired
	ErrUserNotFound     = errors.New("theauth: user not found")
	ErrMagicLinkExpired = models.ErrMagicLinkExpired
	ErrMagicLinkUsed    = errors.New("theauth: magic link already used")
	ErrEmailNotVerified = errors.New("theauth: email not verified")

	// ErrStorageNotFound is the canonical "row missing" sentinel that
	// storage adapters return on lookup misses.
	ErrStorageNotFound = models.ErrStorageNotFound

	// ErrReplayDetected (v0.5) is returned by storage on a WebAuthn sign
	// count update where the new count is not strictly greater than the
	// stored value. The library treats this as a clone-attempt and refuses
	// the login (with the standard 0-stays-0 carve-out for authenticators
	// that do not implement counters; that case is handled by the caller).
	// PR D architecture reorg (2026-06-20): the canonical sentinel lives
	// in internal/webauthn so the extracted Service can return it; root
	// re-aliases here.
	ErrReplayDetected = internalwebauthn.ErrReplayDetected

	// ErrAlreadyEnrolled (v0.5) is returned when /auth/totp/enroll/finish is
	// called against a user who already has a confirmed TOTP secret. Callers
	// must DELETE /auth/totp first to re-enroll. PR D architecture reorg
	// (2026-06-20): canonical sentinel in internal/totp.
	ErrAlreadyEnrolled = internaltotp.ErrAlreadyEnrolled

	// v0.7 sentinels.

	// ErrSCIMRequiresOrganizations is returned by New when Config.SCIM is
	// non-nil but Config.Organizations is nil. SCIM is meaningless without
	// multi-tenancy because every token is bound to one organization.
	ErrSCIMRequiresOrganizations = errors.New("theauth: SCIM requires Organizations to be enabled")
	// ErrSAMLRequiresOrganizations is returned by New when Config.SAML is
	// non-nil but Config.Organizations is nil. Single-tenant SAML is
	// meaningless; per-connection routing keys off organization ownership.
	ErrSAMLRequiresOrganizations = errors.New("theauth: SAML requires Organizations to be enabled")
	// ErrSAMLUnsignedAssertion is returned by FinishSAMLLogin when the
	// inbound SAML Response parses but its assertion is not signed.
	// PR D architecture reorg (2026-06-20): the canonical sentinel lives
	// in internal/saml so the extracted Service can return it; root
	// re-aliases here so errors.Is checks against the root name still
	// match.
	ErrSAMLUnsignedAssertion = internalsaml.ErrSAMLUnsignedAssertion
	// ErrSAMLMissingEmail is returned by FinishSAMLLogin when the mapped
	// email attribute is empty (the find-or-create email fallback path
	// cannot proceed).
	ErrSAMLMissingEmail = internalsaml.ErrSAMLMissingEmail
	// ErrSAMLInvalidAssertion wraps the underlying crewjam/saml validation
	// error for failed signature / conditions / replay checks.
	ErrSAMLInvalidAssertion = internalsaml.ErrSAMLInvalidAssertion
	// ErrLastOwner is returned when an org member removal would leave the
	// organization with zero owners.
	ErrLastOwner = models.ErrLastOwner
	// ErrUnsupportedFilter is returned by the SCIM filter parser on any
	// filter shape outside the documented eq-only whitelist.
	ErrUnsupportedFilter = errors.New("theauth: scim filter not supported")
	// ErrSlugTaken is returned when the supplied organization slug already
	// exists. PR F architecture reorg (2026-06-20): canonical sentinel
	// lives in internal/models so the extracted organization handler
	// package can reference it without importing root.
	ErrSlugTaken = models.ErrSlugTaken

	// v1.0 sentinels.

	// ErrAdminRequiresRBAC is returned by New when Config.Admin is non-nil
	// but Config.RBAC is nil. The admin endpoints are permission-gated and
	// meaningless without RBAC.
	ErrAdminRequiresRBAC = errors.New("theauth: Admin requires RBAC to be enabled")
	// ErrForbidden indicates the caller lacks a required permission for
	// the requested operation. Handlers map this to 403 with code
	// "rbac.forbidden" in the RFC 7807 problem body.
	ErrForbidden = models.ErrForbidden
	// ErrUnknownPermission indicates a permission name not present in the
	// seeded or extended catalog. Mapped to 400 "rbac.unknown_permission".
	ErrUnknownPermission = models.ErrUnknownPermission
	// ErrRoleInUse indicates a DELETE role would leave the organization
	// without any user holding the "users:admin" permission. Mapped to
	// 409 "rbac.role_in_use".
	ErrRoleInUse = models.ErrRoleInUse
	// ErrNoActiveOrg indicates the session has no active_organization_id
	// set. Mapped to 403 "rbac.no_active_org".
	ErrNoActiveOrg = errors.New("theauth: session has no active organization")
	// ErrOrgMismatch indicates the session's active_organization_id does
	// not match the resource organization. Mapped to 403 "rbac.org_mismatch".
	ErrOrgMismatch = errors.New("theauth: session active organization does not match resource")
	// ErrRBACDisabled is returned by RBAC service methods invoked when
	// Config.RBAC is nil. The RequirePermission middleware short-circuits
	// to 500 rather than returning this error directly.
	ErrRBACDisabled = models.ErrRBACDisabled
)

// Stable error codes that callers can switch on. New endpoints return
// TheAuthError; old endpoints keep returning the sentinels above.
// Re-exported from internal/models (PR D architecture reorg, 2026-06-20)
// so internal service packages can construct TheAuthError with these codes
// without taking an import cycle on the root package.
const (
	CodeWeakPassword         = models.CodeWeakPassword
	CodeEmailTaken           = models.CodeEmailTaken
	CodeInvalidCredentials   = models.CodeInvalidCredentials
	CodeRateLimited          = models.CodeRateLimited
	CodePasswordResetExpired = models.CodePasswordResetExpired
	CodePasswordResetInvalid = models.CodePasswordResetInvalid

	// v0.5 codes.
	CodeTOTPRequired    = models.CodeTOTPRequired
	CodeInvalidTOTP     = models.CodeInvalidTOTP
	CodeAlreadyEnrolled = models.CodeAlreadyEnrolled
	CodeWebAuthn        = models.CodeWebAuthn

	// v2.3 identity-linking codes.
	CodeIdentityConflict = models.CodeIdentityConflict
	CodeStepUpRequired   = models.CodeStepUpRequired
	CodeLastAuthMethod   = models.CodeLastAuthMethod
)

// TheAuthError is the structured error type returned by v0.2+ service
// methods. Callers can errors.As-extract it and switch on Code for stable
// handling, or errors.Is-check against a value of the same Code for shorter
// paths.
//
// PR B architecture reorg (2026-06-20): the struct + methods now live in
// internal/models so subpackages can construct it without taking an import
// cycle on the root package. The type alias below preserves the v0.2+
// public name and method set; existing callers compile unchanged.
type TheAuthError = models.TheAuthError

// IdentityConflictError is returned (wrapped inside ErrIdentityConflict) by
// LinkOAuthToCurrentUser when the OAuth account is already bound to a
// different user. errors.As to this type to read ConflictingUserID and
// surface a merge-confirmation flow in the consumer UI.
type IdentityConflictError = models.IdentityConflictError

// NewError constructs a TheAuthError with the supplied code, message, and
// optional wrapped cause. Re-exported from internal/models for the same
// reason as the type alias above.
func NewError(code, message string, inner error) *TheAuthError {
	return models.NewError(code, message, inner)
}

// ---------- v2.0 sentinel errors (OAuth 2.1 AS + DCR + JWKS) ----------
//
// PR B architecture reorg (2026-06-20): the actual error values now live in
// internal/models so the extracted internal/as package can reference them
// without taking an import cycle on the root package. The vars below are
// alias references (same pointer); existing v2.0 callers that
// errors.Is-check against these names keep working unchanged.
// PR G (2026-06-21): merged from the prior errors_v20.go file.

var (
	// ErrASRequiresEncryptionKey is returned by New when
	// Config.AuthorizationServer is non-nil but Config.EncryptionKey is not a
	// 32-byte AES-256 key. The encryption key protects JWKS private keys at
	// rest; running the AS without it would persist signing keys in plaintext.
	ErrASRequiresEncryptionKey = models.ErrASRequiresEncryptionKey

	// ErrASIssuerRequired is returned by New when Config.AuthorizationServer
	// is non-nil but Issuer is empty. RFC 8414 mandates an issuer identifier.
	ErrASIssuerRequired = models.ErrASIssuerRequired

	// ErrASUnsupportedAlg is returned by New for any signing algorithm other
	// than EdDSA. Phase 1 + 2 ships Ed25519 only; RS256 is the documented
	// fallback for a later phase.
	ErrASUnsupportedAlg = models.ErrASUnsupportedAlg

	// ErrOAuthInvalidRequest maps to the OAuth 2.1 "invalid_request" error.
	ErrOAuthInvalidRequest = models.ErrOAuthInvalidRequest

	// ErrOAuthInvalidClient maps to the OAuth 2.1 "invalid_client" error.
	ErrOAuthInvalidClient = models.ErrOAuthInvalidClient

	// ErrOAuthInvalidGrant maps to the OAuth 2.1 "invalid_grant" error,
	// covering expired or replayed authorization codes and refresh tokens.
	ErrOAuthInvalidGrant = models.ErrOAuthInvalidGrant

	// ErrOAuthInvalidScope maps to the OAuth 2.1 "invalid_scope" error.
	ErrOAuthInvalidScope = models.ErrOAuthInvalidScope

	// ErrOAuthUnsupportedGrantType maps to "unsupported_grant_type".
	ErrOAuthUnsupportedGrantType = models.ErrOAuthUnsupportedGrantType

	// ErrOAuthUnsupportedResponseType maps to "unsupported_response_type".
	ErrOAuthUnsupportedResponseType = models.ErrOAuthUnsupportedResponseType

	// ErrOAuthInvalidResource maps to RFC 8707 "invalid_target".
	ErrOAuthInvalidResource = models.ErrOAuthInvalidResource

	// ErrOAuthRegistrationDenied is returned when DCR is attempted without
	// a valid initial access token and AllowAnonymousRegistration is false.
	ErrOAuthRegistrationDenied = models.ErrOAuthRegistrationDenied

	// ErrOAuthRedirectURIMismatch is returned when the token request's
	// redirect_uri does not equal the value bound to the authorization code.
	ErrOAuthRedirectURIMismatch = models.ErrOAuthRedirectURIMismatch

	// ErrOAuthPKCEMismatch is returned when the supplied code_verifier does
	// not match the stored code_challenge under S256.
	ErrOAuthPKCEMismatch = models.ErrOAuthPKCEMismatch

	// ErrOAuthAudienceMismatch is returned at introspection when a token's
	// aud claim does not match the caller's expected resource identifier.
	ErrOAuthAudienceMismatch = models.ErrOAuthAudienceMismatch

	// ErrNotImplemented is returned by service paths that exist for forward
	// compatibility but whose body lands in a later phase. Currently used by
	// agent credential mints for kind = x509 and kind = jwk.
	ErrNotImplemented = models.ErrNotImplemented

	// ErrAgentNotFound is returned by lookups whose target agent is absent.
	ErrAgentNotFound = models.ErrAgentNotFound

	// ErrAgentInactive is returned when an operation depends on an agent
	// whose status is suspended or revoked.
	ErrAgentInactive = models.ErrAgentInactive

	// ErrDelegationNotFound is returned when no delegation_grants row
	// matches the (user, agent, resource) tuple. Token exchange surfaces
	// this as access_denied to the caller.
	ErrDelegationNotFound = models.ErrDelegationNotFound

	// ErrDelegationRevoked is returned when a delegation grant exists but
	// its revoked_at is set. Token exchange surfaces this as access_denied;
	// introspection returns active=false.
	ErrDelegationRevoked = models.ErrDelegationRevoked

	// ErrChainDepthExceeded is returned by the token exchange path when
	// adding the requesting agent to the actor chain would exceed the
	// AgentConfig.MaxChainDepth (default 3).
	ErrChainDepthExceeded = models.ErrChainDepthExceeded

	// ErrSubjectTokenInvalid is returned when the supplied subject_token
	// fails signature, issuer, expiry, or audience checks.
	ErrSubjectTokenInvalid = models.ErrSubjectTokenInvalid

	// ErrActorTokenInvalid is returned when the supplied actor_token fails
	// signature, issuer, expiry, or audience checks, or when it does not
	// resolve to the authenticated agent client.
	ErrActorTokenInvalid = models.ErrActorTokenInvalid

	// ErrAgentRequiresAS is returned by New when Config.AgentIdentity is
	// non-nil but Config.AuthorizationServer is nil. Agents and delegations
	// only make sense alongside the OAuth 2.1 AS that mints their tokens.
	ErrAgentRequiresAS = models.ErrAgentRequiresAS

	// ErrAgentChainDepthTooHigh is returned by New when
	// AgentConfig.MaxChainDepth exceeds the v2.0 hard ceiling of 3.
	ErrAgentChainDepthTooHigh = models.ErrAgentChainDepthTooHigh

	// ErrAccountUXRequiresAgents is returned by New when Config.AccountUX is
	// true but Config.AgentIdentity is nil. The account routes have no
	// service surface to back them otherwise.
	ErrAccountUXRequiresAgents = models.ErrAccountUXRequiresAgents

	// v2.3 identity-linking sentinels.

	// ErrIdentityConflict is returned by LinkOAuthToCurrentUser when the
	// OAuth account being linked is already bound to a different user.
	// errors.As it to *models.IdentityConflictError to read ConflictingUserID.
	ErrIdentityConflict = models.ErrIdentityConflict

	// ErrStepUpRequired is returned by any identity-linking or merge method
	// when the session's AuthLevel is not AuthLevelFull.
	ErrStepUpRequired = models.ErrStepUpRequired

	// ErrLastAuthMethod is returned when an unlink operation would leave
	// the account with zero authentication methods.
	ErrLastAuthMethod = models.ErrLastAuthMethod

	// CIBA (RFC 9509) sentinels.

	// ErrCIBAAuthorizationPending is returned by PollBackchannelToken when
	// the user has not yet approved or denied the request.
	ErrCIBAAuthorizationPending = models.ErrCIBAAuthorizationPending

	// ErrCIBASlowDown is returned when the client polls faster than
	// CIBAConfig.MinPollInterval.
	ErrCIBASlowDown = models.ErrCIBASlowDown

	// ErrCIBAAccessDenied is returned when the user denied the request.
	ErrCIBAAccessDenied = models.ErrCIBAAccessDenied

	// ErrCIBAExpiredToken is returned when the auth_req_id has expired.
	ErrCIBAExpiredToken = models.ErrCIBAExpiredToken

	// ErrCIBAInvalidRequest is returned when required hint parameters are
	// missing or mutually exclusive constraints are violated.
	ErrCIBAInvalidRequest = models.ErrCIBAInvalidRequest

	// ErrCIBADisabled is returned when a CIBA operation is attempted but
	// CIBA is not enabled (Config.AuthorizationServer.CIBA is nil or the
	// storage does not implement CIBAStorage).
	ErrCIBADisabled = models.ErrCIBADisabled

	// ErrCIBAUserMismatch is returned by ApproveBackchannelAuth /
	// DenyBackchannelAuth when the supplied userID does not match the
	// resolved subject on the pending request.
	ErrCIBAUserMismatch = models.ErrCIBAUserMismatch
)

// OAuth 2.1 standard error codes returned in JSON error bodies.
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
