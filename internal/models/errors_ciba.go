package models

import "errors"

// CIBA sentinel errors. Re-exported from the root package in errors_ciba.go
// via var aliases for backward compatibility.
var (
	// ErrCIBAAuthorizationPending is returned by the token endpoint poll
	// when the user has not yet approved or denied the request.
	ErrCIBAAuthorizationPending = errors.New("theauth: authorization_pending")

	// ErrCIBASlowDown is returned when the client polls faster than
	// MinPollInterval. The client should double its polling interval.
	ErrCIBASlowDown = errors.New("theauth: slow_down")

	// ErrCIBAAccessDenied is returned when the user denied the request.
	ErrCIBAAccessDenied = errors.New("theauth: access_denied (ciba)")

	// ErrCIBAExpiredToken is returned when the auth_req_id has passed its
	// ExpiresAt deadline.
	ErrCIBAExpiredToken = errors.New("theauth: expired_token")

	// ErrCIBAInvalidRequest is returned when required hint parameters are
	// missing or mutually exclusive constraints are violated.
	ErrCIBAInvalidRequest = errors.New("theauth: invalid_request (ciba)")

	// ErrCIBADisabled is returned when a CIBA endpoint is called but
	// Config.CIBA is nil, or the storage does not implement CIBAStorage.
	ErrCIBADisabled = errors.New("theauth: CIBA not enabled")

	// ErrCIBAUserMismatch is returned by ApproveBackchannelAuth /
	// DenyBackchannelAuth when the supplied userID does not match the
	// resolved subject on the pending request.
	ErrCIBAUserMismatch = errors.New("theauth: ciba user mismatch")
)
