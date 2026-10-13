package theauth

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// AccountState holds per-user lifecycle flags (forced password change,
// disabled).
type AccountState = models.AccountState

// TrustedDevice is a remember-this-device record. Only the hash of its cookie
// token is stored.
type TrustedDevice = models.TrustedDevice

// AccountStateStorage is the optional capability behind forced password change
// and account disable. It is detected by type assertion and is not part of
// Storage. Without it those features answer ErrStorageMissingCapability and
// sign-in is unchanged. Memory, SQLite, Postgres and MySQL implement it.
type AccountStateStorage interface {
	// AccountStateByUserID returns the user's flags. A user with no recorded
	// state returns the zero AccountState and no error.
	AccountStateByUserID(ctx context.Context, userID ULID) (AccountState, error)
	// SetMustChangePassword sets or clears the forced password change flag.
	// It returns ErrStorageNotFound for an unknown user.
	SetMustChangePassword(ctx context.Context, userID ULID, required bool) error
	// SetUserDisabledAt disables the user at the given time, or re-enables it
	// when at is nil. It returns ErrStorageNotFound for an unknown user.
	SetUserDisabledAt(ctx context.Context, userID ULID, at *time.Time) error
}

// AccountDeleteStorage is the optional capability behind account deletion.
// DeleteUserCascade removes the user and every row that belongs to it
// (sessions, tokens, identities, passkeys, TOTP, API tokens, memberships,
// account state, trusted devices) so nothing is left behind. Audit rows are
// kept with the actor cleared. It returns ErrStorageNotFound for an unknown
// user.
type AccountDeleteStorage interface {
	DeleteUserCascade(ctx context.Context, userID ULID) error
}

// TrustedDeviceStorage is the optional capability behind
// Config.TrustedDevices. Lookups return ErrStorageNotFound on a miss.
type TrustedDeviceStorage interface {
	InsertTrustedDevice(ctx context.Context, d TrustedDevice) error
	// TrustedDeviceByTokenHash returns the record for userID and hash,
	// revoked or expired rows included; callers check RevokedAt and ExpiresAt.
	TrustedDeviceByTokenHash(ctx context.Context, userID ULID, hash []byte) (*TrustedDevice, error)
	// ListTrustedDevices returns the user's unrevoked, unexpired devices,
	// newest first.
	ListTrustedDevices(ctx context.Context, userID ULID) ([]TrustedDevice, error)
	// TouchTrustedDevice sets LastUsedAt.
	TouchTrustedDevice(ctx context.Context, id ULID, at time.Time) error
	// RevokeTrustedDevice revokes one device owned by userID. It returns
	// ErrStorageNotFound when no such live device exists.
	RevokeTrustedDevice(ctx context.Context, userID, id ULID) error
	// RevokeUserTrustedDevices revokes every live device of userID and
	// returns how many it revoked.
	RevokeUserTrustedDevices(ctx context.Context, userID ULID) (int, error)
}
