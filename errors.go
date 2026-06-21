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
	// exists.
	ErrSlugTaken = errors.New("theauth: organization slug already taken")

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

// NewError constructs a TheAuthError with the supplied code, message, and
// optional wrapped cause. Re-exported from internal/models for the same
// reason as the type alias above.
func NewError(code, message string, inner error) *TheAuthError {
	return models.NewError(code, message, inner)
}
