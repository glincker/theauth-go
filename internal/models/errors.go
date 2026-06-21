package models

import "errors"

// Sentinel errors that the storage layer and service code share. These names
// are re-exported from the root package (github.com/glincker/theauth-go)
// via var aliases for backward compatibility with v0.1+ callers that
// errors.Is-check against them.
//
// Only model-layer sentinels live here: storage misses, expiry states,
// RBAC catalog rejections, organization invariants. Service-flow and
// wire-protocol sentinels (OAuth error strings, password reset codes,
// admin precondition checks) stay in the root package.
var (
	// ErrInvalidToken is returned by any service that fails to authenticate
	// or validate a presented opaque token.
	ErrInvalidToken = errors.New("theauth: invalid token")

	// ErrSessionExpired is returned by session lookups whose row exists but
	// is past its ExpiresAt or has a non-nil RevokedAt.
	ErrSessionExpired = errors.New("theauth: session expired")

	// ErrMagicLinkExpired is returned by magic link consumption when the
	// row is past ExpiresAt or already used.
	ErrMagicLinkExpired = errors.New("theauth: magic link expired")

	// ErrStorageNotFound is the canonical "row missing" sentinel that storage
	// adapters return on lookup misses. Lives in the models package so service
	// code can errors.Is-check without importing the storage package
	// (which would create an import cycle).
	ErrStorageNotFound = errors.New("theauth: storage row not found")

	// ErrLastOwner is returned when an org member removal would leave the
	// organization with zero owners.
	ErrLastOwner = errors.New("theauth: cannot remove the last owner")

	// ErrForbidden indicates the caller lacks a required permission for
	// the requested operation. Handlers map this to 403 with code
	// "rbac.forbidden" in the RFC 7807 problem body.
	ErrForbidden = errors.New("theauth: forbidden")

	// ErrUnknownPermission indicates a permission name not present in the
	// seeded or extended catalog. Mapped to 400 "rbac.unknown_permission".
	ErrUnknownPermission = errors.New("theauth: unknown permission")

	// ErrRoleInUse indicates a DELETE role would leave the organization
	// without any user holding the "users:admin" permission. Mapped to
	// 409 "rbac.role_in_use".
	ErrRoleInUse = errors.New("theauth: role in use")

	// ErrRBACDisabled is returned by RBAC service methods invoked when
	// Config.RBAC is nil. The RequirePermission middleware short-circuits
	// to 500 rather than returning this error directly.
	ErrRBACDisabled = errors.New("theauth: RBAC disabled (Config.RBAC is nil)")
)
