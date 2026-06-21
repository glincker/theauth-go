package theauth

import (
	"context"

	"github.com/glincker/theauth-go/internal/password"
)

// Password forwarders. PR D architecture reorg (2026-06-20) moved the
// implementations to internal/password; the unexported signupWithPassword /
// signinWithPassword / requestPasswordReset / requestPasswordResetForTest /
// resetPassword entry points kept their exact signatures so callers in
// this package (handlers_password, export_test) continue to compile
// unchanged.
//
// MinPasswordLength and PasswordResetTTL are re-exported from
// internal/password so the v0.2 public surface is unchanged.

// MinPasswordLength is enforced at the library level (NIST 2024 baseline).
const MinPasswordLength = password.MinPasswordLength

// PasswordResetTTL is how long a reset token stays valid after issuance.
const PasswordResetTTL = password.PasswordResetTTL

// SigninStep mirrors the v0.5 step indicator returned by signinWithPassword.
type SigninStep = password.SigninStep

// SigninStep values re-exported for the v0.5 public surface.
const (
	SigninStepFull         = password.SigninStepFull
	SigninStepTOTPRequired = password.SigninStepTOTPRequired
)

// validateEmail forwards to password.ValidateEmail for the fuzz seam.
// Used by the export_test.go ValidateEmailForTest shim.
func validateEmail(raw string) (string, error) {
	return password.ValidateEmail(raw)
}

// signupWithPassword creates a new user with email + password credentials
// and issues a session.
func (a *TheAuth) signupWithPassword(ctx context.Context, emailAddr, pw string) (*User, string, error) {
	return a.passwordSvc.Signup(ctx, emailAddr, pw)
}

// signinWithPassword verifies credentials and issues a session.
func (a *TheAuth) signinWithPassword(ctx context.Context, emailAddr, pw, userAgent, ip string) (string, *User, SigninStep, error) {
	return a.passwordSvc.Signin(ctx, emailAddr, pw, userAgent, ip)
}

// requestPasswordReset always returns nil error on "user does not exist"
// to prevent email enumeration.
func (a *TheAuth) requestPasswordReset(ctx context.Context, emailAddr string) error {
	return a.passwordSvc.RequestReset(ctx, emailAddr)
}

// requestPasswordResetForTest is the testable variant; returns the raw
// token when one is minted, "" when the email does not exist.
func (a *TheAuth) requestPasswordResetForTest(ctx context.Context, emailAddr string) (string, error) {
	return a.passwordSvc.RequestResetForTest(ctx, emailAddr)
}

// resetPassword atomically consumes a reset token, updates the user's
// password, and revokes all existing sessions.
func (a *TheAuth) resetPassword(ctx context.Context, token, newPassword string) error {
	return a.passwordSvc.Reset(ctx, token, newPassword)
}
