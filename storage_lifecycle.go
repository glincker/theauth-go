package theauth

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// AccountState holds per-user lifecycle flags (forced password change, disabled).
type AccountState = models.AccountState

// TrustedDevice is a remember-this-device record.
type TrustedDevice = models.TrustedDevice

// AccountStateStorage is the optional capability behind forced password change and account disable.
// Without it those features return ErrStorageMissingCapability and sign-in is unchanged.
type AccountStateStorage interface {
	AccountStateByUserID(ctx context.Context, userID ULID) (AccountState, error)
	SetMustChangePassword(ctx context.Context, userID ULID, required bool) error
	SetUserDisabledAt(ctx context.Context, userID ULID, at *time.Time) error
}

// AccountDeleteStorage is the optional capability behind account deletion. DeleteUserCascade
// removes the user and every row that belongs to it, so nothing is left behind.
type AccountDeleteStorage interface {
	DeleteUserCascade(ctx context.Context, userID ULID) error
}

// TrustedDeviceStorage is the optional capability behind Config.TrustedDevices.
type TrustedDeviceStorage interface {
	InsertTrustedDevice(ctx context.Context, d TrustedDevice) error
	TrustedDeviceByTokenHash(ctx context.Context, userID ULID, hash []byte) (*TrustedDevice, error)
	// ListTrustedDevices returns the user's unrevoked, unexpired devices, newest first.
	ListTrustedDevices(ctx context.Context, userID ULID) ([]TrustedDevice, error)
	TouchTrustedDevice(ctx context.Context, id ULID, at time.Time) error
	RevokeTrustedDevice(ctx context.Context, userID, id ULID) error
	RevokeUserTrustedDevices(ctx context.Context, userID ULID) (int, error)
}
