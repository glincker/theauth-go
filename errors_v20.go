package theauth

import "github.com/glincker/theauth-go/internal/models"

// v2.0 sentinel errors. Phase 1 + 2 scope: OAuth 2.1 AS + DCR + JWKS.
//
// PR B architecture reorg (2026-06-20): the actual error values now live in
// internal/models so the extracted internal/as package can reference them
// without taking an import cycle on the root package. The vars below are
// alias references (same pointer); existing v2.0 callers that
// errors.Is-check against these names keep working unchanged.

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
