package theauth

import "errors"

// Sentinel errors — retained for backward compatibility with v0.1 callers
// that errors.Is-check against them. New code should prefer TheAuthError +
// the Code* constants below.
var (
	ErrInvalidToken     = errors.New("theauth: invalid token")
	ErrSessionExpired   = errors.New("theauth: session expired")
	ErrUserNotFound     = errors.New("theauth: user not found")
	ErrMagicLinkExpired = errors.New("theauth: magic link expired")
	ErrMagicLinkUsed    = errors.New("theauth: magic link already used")
	ErrEmailNotVerified = errors.New("theauth: email not verified")

	// ErrStorageNotFound is the canonical "row missing" sentinel that storage
	// adapters return on lookup misses. Lives in the root package so service
	// code can errors.Is-check without importing the storage package
	// (which would create an import cycle).
	ErrStorageNotFound = errors.New("theauth: storage row not found")

	// ErrReplayDetected (v0.5) is returned by storage on a WebAuthn sign
	// count update where the new count is not strictly greater than the
	// stored value. The library treats this as a clone-attempt and refuses
	// the login (with the standard 0-stays-0 carve-out for authenticators
	// that do not implement counters; that case is handled by the caller).
	ErrReplayDetected = errors.New("theauth: webauthn sign count replay detected")

	// ErrAlreadyEnrolled (v0.5) is returned when /auth/totp/enroll/finish is
	// called against a user who already has a confirmed TOTP secret. Callers
	// must DELETE /auth/totp first to re-enroll.
	ErrAlreadyEnrolled = errors.New("theauth: totp already enrolled")
)

// Stable error codes that callers can switch on. New endpoints return
// TheAuthError; old endpoints keep returning the sentinels above.
const (
	CodeWeakPassword         = "weak_password"
	CodeEmailTaken           = "email_taken"
	CodeInvalidCredentials   = "invalid_credentials"
	CodeRateLimited          = "rate_limited"
	CodePasswordResetExpired = "password_reset_expired"
	CodePasswordResetInvalid = "password_reset_invalid"

	// v0.5 codes.
	CodeTOTPRequired    = "totp_required"
	CodeInvalidTOTP     = "invalid_totp"
	CodeAlreadyEnrolled = "already_enrolled"
	CodeWebAuthn        = "webauthn_error"
)

// TheAuthError is the structured error type returned by v0.2+ service methods.
// Callers can errors.As-extract it and switch on Code for stable handling,
// or errors.Is-check against a value of the same Code for shorter paths.
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

// Is reports whether target is a *TheAuthError with the same Code, OR is the
// Inner cause. This lets callers do errors.Is(err, &TheAuthError{Code: ...})
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
