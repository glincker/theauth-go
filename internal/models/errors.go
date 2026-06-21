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

	// v2.0 OAuth 2.1 authorization server sentinels. Lifted to the models
	// package (PR B architecture reorg, 2026-06-20) so the internal/as
	// extraction can reference them without taking an import cycle on the
	// root package. Re-exported from root errors_v20.go as var aliases for
	// backward compatibility with v2.0 callers that errors.Is-check them.

	// ErrASRequiresEncryptionKey is returned by New when
	// Config.AuthorizationServer is non-nil but Config.EncryptionKey is not a
	// 32-byte AES-256 key.
	ErrASRequiresEncryptionKey = errors.New("theauth: AuthorizationServer requires Config.EncryptionKey (32 bytes)")

	// ErrASIssuerRequired is returned by New when Config.AuthorizationServer
	// is non-nil but Issuer is empty.
	ErrASIssuerRequired = errors.New("theauth: AuthorizationServer.Issuer is required")

	// ErrASUnsupportedAlg is returned by New for any signing algorithm other
	// than EdDSA.
	ErrASUnsupportedAlg = errors.New("theauth: AuthorizationServer.SigningAlg must be EdDSA")

	// ErrOAuthInvalidRequest maps to the OAuth 2.1 "invalid_request" error.
	ErrOAuthInvalidRequest = errors.New("theauth: invalid_request")

	// ErrOAuthInvalidClient maps to the OAuth 2.1 "invalid_client" error.
	ErrOAuthInvalidClient = errors.New("theauth: invalid_client")

	// ErrOAuthInvalidGrant maps to the OAuth 2.1 "invalid_grant" error.
	ErrOAuthInvalidGrant = errors.New("theauth: invalid_grant")

	// ErrOAuthInvalidScope maps to the OAuth 2.1 "invalid_scope" error.
	ErrOAuthInvalidScope = errors.New("theauth: invalid_scope")

	// ErrOAuthUnsupportedGrantType maps to "unsupported_grant_type".
	ErrOAuthUnsupportedGrantType = errors.New("theauth: unsupported_grant_type")

	// ErrOAuthUnsupportedResponseType maps to "unsupported_response_type".
	ErrOAuthUnsupportedResponseType = errors.New("theauth: unsupported_response_type")

	// ErrOAuthInvalidResource maps to RFC 8707 "invalid_target".
	ErrOAuthInvalidResource = errors.New("theauth: invalid_target")

	// ErrOAuthRegistrationDenied is returned when DCR is attempted without a
	// valid initial access token and AllowAnonymousRegistration is false.
	ErrOAuthRegistrationDenied = errors.New("theauth: registration not permitted")

	// ErrOAuthRedirectURIMismatch is returned when the token request's
	// redirect_uri does not equal the value bound to the authorization code.
	ErrOAuthRedirectURIMismatch = errors.New("theauth: redirect_uri mismatch")

	// ErrOAuthPKCEMismatch is returned when the supplied code_verifier does
	// not match the stored code_challenge under S256.
	ErrOAuthPKCEMismatch = errors.New("theauth: pkce verification failed")

	// ErrOAuthAudienceMismatch is returned at introspection when a token's
	// aud claim does not match the caller's expected resource identifier.
	ErrOAuthAudienceMismatch = errors.New("theauth: token audience mismatch")

	// ErrNotImplemented is returned by service paths that exist for forward
	// compatibility but whose body lands in a later phase.
	ErrNotImplemented = errors.New("theauth: not implemented")

	// ErrAgentNotFound is returned by lookups whose target agent is absent.
	ErrAgentNotFound = errors.New("theauth: agent not found")

	// ErrAgentInactive is returned when an operation depends on an agent
	// whose status is suspended or revoked.
	ErrAgentInactive = errors.New("theauth: agent inactive")

	// ErrDelegationNotFound is returned when no delegation_grants row
	// matches the (user, agent, resource) tuple.
	ErrDelegationNotFound = errors.New("theauth: delegation grant not found")

	// ErrDelegationRevoked is returned when a delegation grant exists but
	// its revoked_at is set.
	ErrDelegationRevoked = errors.New("theauth: delegation grant revoked")

	// ErrChainDepthExceeded is returned by the token exchange path when
	// adding the requesting agent to the actor chain would exceed the
	// AgentConfig.MaxChainDepth (default 3).
	ErrChainDepthExceeded = errors.New("theauth: actor chain depth exceeded")

	// ErrSubjectTokenInvalid is returned when the supplied subject_token
	// fails signature, issuer, expiry, or audience checks.
	ErrSubjectTokenInvalid = errors.New("theauth: subject_token invalid")

	// ErrActorTokenInvalid is returned when the supplied actor_token fails
	// signature, issuer, expiry, or audience checks, or when it does not
	// resolve to the authenticated agent client.
	ErrActorTokenInvalid = errors.New("theauth: actor_token invalid")

	// ErrAgentRequiresAS is returned by New when Config.AgentIdentity is
	// non-nil but Config.AuthorizationServer is nil.
	ErrAgentRequiresAS = errors.New("theauth: AgentIdentity requires AuthorizationServer to be configured")

	// ErrAgentChainDepthTooHigh is returned by New when
	// AgentConfig.MaxChainDepth exceeds the v2.0 hard ceiling of 3.
	ErrAgentChainDepthTooHigh = errors.New("theauth: AgentConfig.MaxChainDepth must not exceed 3 in v2.0")

	// ErrAccountUXRequiresAgents is returned by New when Config.AccountUX is
	// true but Config.AgentIdentity is nil.
	ErrAccountUXRequiresAgents = errors.New("theauth: AccountUX requires AgentIdentity to be configured")

	// ErrStorageMissingOAuthMethods is returned by New when
	// Config.AuthorizationServer is non-nil but the supplied Storage does
	// not satisfy the OAuthServerStorage extension. Catches in-memory
	// adapters that pre-date the v2.0 storage surface.
	ErrStorageMissingOAuthMethods = errors.New("theauth: Storage does not implement OAuthServerStorage")
)

// TheAuthError is the structured error type returned by v0.2+ service
// methods. Callers can errors.As-extract it and switch on Code for stable
// handling, or errors.Is-check against a value of the same Code for shorter
// paths. Lifted to the models package (PR B architecture reorg, 2026-06-20)
// so internal subpackages can construct it without taking an import cycle
// on the root package. Re-exported from root errors.go as a type alias.
type TheAuthError struct {
	Code    string
	Message string
	Inner   error
}

// NewError constructs a TheAuthError with the supplied code, message, and
// optional wrapped cause.
func NewError(code, message string, inner error) *TheAuthError {
	return &TheAuthError{Code: code, Message: message, Inner: inner}
}

// Error returns the canonical string form for log output.
func (e *TheAuthError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return "theauth: " + e.Code
	}
	return "theauth: " + e.Code + ": " + e.Message
}

// Unwrap exposes the inner error for errors.Is/errors.As traversal.
func (e *TheAuthError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Inner
}

// Is reports whether target is a *TheAuthError with the same Code, OR is
// the Inner cause. Lets callers do errors.Is(err, &TheAuthError{Code: ...})
// for code-only comparisons without caring about the message or inner cause.
func (e *TheAuthError) Is(target error) bool {
	if e == nil || target == nil {
		return false
	}
	t, ok := target.(*TheAuthError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}
