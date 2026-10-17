package theauth

import (
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// SessionOverflow says what happens when a sign-in would exceed SessionPolicy.MaxConcurrentSessions.
type SessionOverflow string

const (
	SessionEvictOldest SessionOverflow = "evict_oldest"
	// SessionReject refuses the new sign-in with CodeSessionLimit.
	SessionReject SessionOverflow = "reject"
)

// SessionPolicy caps how many full sessions one user may hold. Pending 2FA sessions do not count.
// The check is best effort under concurrency. It needs SessionManagementStorage.
type SessionPolicy struct {
	MaxConcurrentSessions int
	Overflow              SessionOverflow
}

// TrustedDevicesConfig enables remember-this-device for TOTP. After a successful second factor the
// client may send {"rememberDevice": true}; the library sets a signed cookie and stores only its
// hash. Trust is revoked on password change, TOTP removal, or through the trusted-device list.
// Needs Config.TOTP and TrustedDeviceStorage.
type TrustedDevicesConfig struct {
	TTL        time.Duration
	CookieName string
}

// AccountDeletionConfig mounts DELETE /account for self-service deletion. Needs AccountDeleteStorage.
type AccountDeletionConfig struct {
	RecentAuthMaxAge time.Duration
}

// ErrAccountStateDisabled is returned by the forced-password-change and disable APIs when
// Config.AccountState is false.
var ErrAccountStateDisabled = models.ErrAccountStateDisabled

// TrustedDeviceInfo is the end-user view of one trusted device.
type TrustedDeviceInfo struct {
	ID          ULID      `json:"id"`
	DeviceLabel string    `json:"deviceLabel"`
	IPPrefix    string    `json:"ipPrefix,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	LastUsedAt  time.Time `json:"lastUsedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// ResetPasswordOption customizes ResetPasswordAdmin.
type ResetPasswordOption func(*resetPasswordOptions)

type resetPasswordOptions struct{ requireChange bool }

// RequirePasswordChange makes ResetPasswordAdmin force a new password before the next sign-in
// completes. Needs Config.AccountState.
func RequirePasswordChange() ResetPasswordOption {
	return func(o *resetPasswordOptions) { o.requireChange = true }
}
