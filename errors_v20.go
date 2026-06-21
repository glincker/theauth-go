package theauth

import "errors"

// v2.0 sentinel errors. Phase 1 + 2 scope: OAuth 2.1 AS + DCR + JWKS.

var (
	// ErrASRequiresEncryptionKey is returned by New when
	// Config.AuthorizationServer is non-nil but Config.EncryptionKey is not a
	// 32-byte AES-256 key. The encryption key protects JWKS private keys at
	// rest; running the AS without it would persist signing keys in plaintext.
	ErrASRequiresEncryptionKey = errors.New("theauth: AuthorizationServer requires Config.EncryptionKey (32 bytes)")

	// ErrASIssuerRequired is returned by New when Config.AuthorizationServer
	// is non-nil but Issuer is empty. RFC 8414 mandates an issuer identifier.
	ErrASIssuerRequired = errors.New("theauth: AuthorizationServer.Issuer is required")

	// ErrASUnsupportedAlg is returned by New for any signing algorithm other
	// than EdDSA. Phase 1 + 2 ships Ed25519 only; RS256 is the documented
	// fallback for a later phase.
	ErrASUnsupportedAlg = errors.New("theauth: AuthorizationServer.SigningAlg must be EdDSA")

	// ErrOAuthInvalidRequest maps to the OAuth 2.1 "invalid_request" error.
	ErrOAuthInvalidRequest = errors.New("theauth: invalid_request")

	// ErrOAuthInvalidClient maps to the OAuth 2.1 "invalid_client" error.
	ErrOAuthInvalidClient = errors.New("theauth: invalid_client")

	// ErrOAuthInvalidGrant maps to the OAuth 2.1 "invalid_grant" error,
	// covering expired or replayed authorization codes and refresh tokens.
	ErrOAuthInvalidGrant = errors.New("theauth: invalid_grant")

	// ErrOAuthInvalidScope maps to the OAuth 2.1 "invalid_scope" error.
	ErrOAuthInvalidScope = errors.New("theauth: invalid_scope")

	// ErrOAuthUnsupportedGrantType maps to "unsupported_grant_type".
	ErrOAuthUnsupportedGrantType = errors.New("theauth: unsupported_grant_type")

	// ErrOAuthUnsupportedResponseType maps to "unsupported_response_type".
	ErrOAuthUnsupportedResponseType = errors.New("theauth: unsupported_response_type")

	// ErrOAuthInvalidResource maps to RFC 8707 "invalid_target".
	ErrOAuthInvalidResource = errors.New("theauth: invalid_target")

	// ErrOAuthRegistrationDenied is returned when DCR is attempted without
	// a valid initial access token and AllowAnonymousRegistration is false.
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
