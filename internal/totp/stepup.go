package totp

import (
	"context"

	"github.com/glincker/theauth-go/internal/models"
	otptotp "github.com/pquerna/otp/totp"
)

// CheckCode validates a TOTP code for userID without touching any session
// state. Failures count against sessID's brute-force budget, which revokes
// the session after the same limit as the pending-2FA path.
func (s *Service) CheckCode(ctx context.Context, sessID, userID models.ULID, code string) error {
	secret, err := s.decryptSecret(ctx, userID)
	if err != nil {
		return err
	}
	if !otptotp.Validate(code, secret) {
		s.recordPendingFailure(ctx, sessID, userID)
		return models.NewError(models.CodeInvalidTOTP, "invalid code", nil)
	}
	s.clearPendingFailure(sessID)
	return nil
}
