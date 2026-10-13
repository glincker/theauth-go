package theauth

import (
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// SessionOverflow says what happens when a sign-in would exceed
// SessionPolicy.MaxConcurrentSessions.
type SessionOverflow string

const (
	// SessionEvictOldest revokes the user's oldest sessions to make room.
	// It is the default.
	SessionEvictOldest SessionOverflow = "evict_oldest"
	// SessionReject refuses the new sign-in with CodeSessionLimit.
	SessionReject SessionOverflow = "reject"
)

// SessionPolicy bounds how many full sessions one user may hold at once. It
// needs a storage implementing SessionManagementStorage. Pending 2FA
// sessions do not count. The check is best effort under concurrency: two
// simultaneous sign-ins can both pass it.
type SessionPolicy struct {
	// MaxConcurrentSessions is the cap. Zero disables it.
	MaxConcurrentSessions int
	// Overflow is SessionEvictOldest (default) or SessionReject.
	Overflow SessionOverflow
}

// TrustedDevicesConfig enables remember-this-device for TOTP. After a
// successful TOTP or recovery-code step the client may send
// {"rememberDevice": true}; the library then sets a signed cookie and stores
// only its hash. Later password sign-ins from that device skip the TOTP
// prompt until the window ends. Trust is revoked on password change, when
// TOTP is removed, and through the trusted-device list. It needs Config.TOTP
// and a storage implementing TrustedDeviceStorage.
type TrustedDevicesConfig struct {
	// TTL is the trust window. Default 30 days.
	TTL time.Duration
	// CookieName defaults to "theauth_trusted_device".
	CookieName string
}

// AccountDeletionConfig mounts DELETE /account for self-service deletion.
// It needs a storage implementing AccountDeleteStorage.
type AccountDeletionConfig struct {
	// RecentAuthMaxAge is how recently the session must have authenticated
	// (sign-in or step-up). Default 10 minutes.
	RecentAuthMaxAge time.Duration
}

// ErrAccountStateDisabled is returned by the forced-password-change and
// disable APIs when Config.AccountState is false.
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

// RequirePasswordChange makes ResetPasswordAdmin flag the account so the user
// must choose a new password before the next sign-in completes (it returns
// CodePasswordChangeRequired until the user finishes a password reset). It
// needs Config.AccountState.
func RequirePasswordChange() ResetPasswordOption {
	return func(o *resetPasswordOptions) { o.requireChange = true }
}
