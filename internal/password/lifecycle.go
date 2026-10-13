package password

import (
	"context"
	"errors"
	"log/slog"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// AccountLifecycle connects password flows to account state. All methods are
// optional behavior behind Config.Account; a nil value keeps the original
// flow.
type AccountLifecycle interface {
	// CheckSignin returns a non-nil error when userID may not start a session,
	// for example CodePasswordChangeRequired or CodeAccountDisabled.
	CheckSignin(ctx context.Context, userID models.ULID) error
	// PasswordChanged runs after a password was replaced by reset or admin
	// reset: it clears the forced-change flag and revokes trusted devices.
	PasswordChanged(ctx context.Context, userID models.ULID) error
	// RequireChange flags userID so the next sign-in must change the password.
	RequireChange(ctx context.Context, userID models.ULID) error
}

// TrustedDeviceChecker reports whether a remember-device cookie is a live
// trusted device of the user.
type TrustedDeviceChecker interface {
	Trusted(ctx context.Context, userID models.ULID, cookieValue string) bool
}

type deviceKey struct{}

// WithDeviceToken attaches the trusted-device cookie value of the request so
// Signin can skip the TOTP prompt for a remembered device.
func WithDeviceToken(ctx context.Context, cookieValue string) context.Context {
	return context.WithValue(ctx, deviceKey{}, cookieValue)
}

func deviceToken(ctx context.Context) string {
	v, _ := ctx.Value(deviceKey{}).(string)
	return v
}

// trustedDevice reports whether the request carries a live trusted device.
func (s *Service) trustedDevice(ctx context.Context, userID models.ULID) bool {
	if s.cfg.Devices == nil {
		return false
	}
	tok := deviceToken(ctx)
	return tok != "" && s.cfg.Devices.Trusted(ctx, userID, tok)
}

// checkAccount runs the account gate and audits a refusal.
func (s *Service) checkAccount(ctx context.Context, user *models.User, userAgent, ip string) error {
	if s.cfg.Account == nil {
		return nil
	}
	err := s.cfg.Account.CheckSignin(ctx, user.ID)
	if err == nil {
		return nil
	}
	reason := "blocked"
	var te *models.TheAuthError
	if errors.As(err, &te) {
		reason = te.Code
	}
	s.emitLoginFailed(ctx, &user.ID, userAgent, ip, reason)
	return err
}

// passwordChanged tells the lifecycle hook about a replaced password. A
// failure is logged; the password change itself already succeeded.
func (s *Service) passwordChanged(ctx context.Context, userID models.ULID) {
	if s.cfg.Account == nil {
		return
	}
	if err := s.cfg.Account.PasswordChanged(ctx, userID); err != nil {
		slog.Error("theauth: account lifecycle after password change failed", "user_id", userID.String(), "err", err.Error())
	}
}
