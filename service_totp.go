package theauth

import (
	"context"

	"github.com/glincker/theauth-go/internal/totp"
)

// TOTP forwarders. PR D architecture reorg (2026-06-20) moved the
// implementations to internal/totp; the public BeginTOTPEnrollment /
// FinishTOTPEnrollment / VerifyTOTP / ConsumeRecoveryCode /
// IssuePending2FA entry points kept their exact signatures so callers in
// this package (handlers_totp, service_password, export_test) continue to
// compile unchanged.

// EnrollTOTPResult is returned by BeginTOTPEnrollment for the caller to
// render. Re-exported as an alias so the v0.5 public surface is
// unchanged.
type EnrollTOTPResult = totp.EnrollResult

// BeginTOTPEnrollment generates a fresh shared secret and otpauth URL,
// returns them to the caller (the secret is displayed exactly once), and
// stashes the plaintext in the in-memory pending map.
func (a *TheAuth) BeginTOTPEnrollment(ctx context.Context, userID ULID, accountName string) (EnrollTOTPResult, error) {
	return a.totpSvc.BeginEnrollment(ctx, userID, accountName)
}

// FinishTOTPEnrollment validates one code against the pending secret,
// confirms the row, generates recovery codes, and returns them to the
// caller.
func (a *TheAuth) FinishTOTPEnrollment(ctx context.Context, userID ULID, enrollmentID, code string) ([]string, error) {
	return a.totpSvc.FinishEnrollment(ctx, userID, enrollmentID, code)
}

// IssuePending2FA mints a short-lived session whose AuthLevel is
// AuthLevelPending2FA.
func (a *TheAuth) IssuePending2FA(ctx context.Context, userID ULID, ua, ip string) (string, Session, error) {
	return a.totpSvc.IssuePending2FA(ctx, userID, ua, ip)
}

// VerifyTOTP consumes a 6-digit code against the user's confirmed secret,
// upgrades their pending session to full, and returns the (same) token
// with the upgraded session row.
func (a *TheAuth) VerifyTOTP(ctx context.Context, pendingSessionToken, code string) (string, Session, error) {
	return a.totpSvc.Verify(ctx, pendingSessionToken, code)
}

// ConsumeRecoveryCode upgrades a pending session by consuming one unused
// recovery code.
func (a *TheAuth) ConsumeRecoveryCode(ctx context.Context, pendingSessionToken, code string) (string, Session, error) {
	return a.totpSvc.ConsumeRecoveryCode(ctx, pendingSessionToken, code)
}
