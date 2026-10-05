package totp

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// CheckCode validates a TOTP code for userID without touching any session
// state. Failures count against sessID's brute-force budget, which revokes
// the session after the same limit as the pending-2FA path.
func (s *Service) CheckCode(ctx context.Context, sessID, userID models.ULID, code string) error {
	if err := s.checkMFA(ctx, userID); err != nil {
		return err
	}
	secret, err := s.decryptSecret(ctx, userID)
	if err != nil {
		return err
	}
	step, valid := matchStep(code, secret, time.Now())
	if valid {
		fresh, aerr := s.advanceStep(ctx, userID, step)
		if aerr != nil {
			return aerr
		}
		valid = fresh
	}
	if !valid {
		s.mfaFailed(ctx, userID)
		s.emitMFA(ctx, userID, "totp", false)
		s.recordPendingFailure(ctx, sessID, userID)
		return models.NewError(models.CodeInvalidTOTP, "invalid code", nil)
	}
	s.mfaSucceeded(ctx, userID)
	s.clearPendingFailure(sessID)
	return nil
}
