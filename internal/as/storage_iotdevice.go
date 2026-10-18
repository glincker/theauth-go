package as

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// DeviceIdentityStorage is the persistence extension for constrained devices and their join tokens.
// Without it Config.DeviceTokens is rejected at startup. Redeem and revoke are conditional updates,
// so concurrent callers cannot both win.
type DeviceIdentityStorage interface {
	InsertDevice(ctx context.Context, d models.Device) error
	DeviceByID(ctx context.Context, id models.ULID) (*models.Device, error)
	ListDevices(ctx context.Context, orgID *models.ULID) ([]models.Device, error)
	RevokeDevice(ctx context.Context, id models.ULID, at time.Time) (bool, error)
	TouchDevice(ctx context.Context, id models.ULID, at time.Time) error
	// SuspendDevice moves an active device to suspended and reports whether it changed. A revoked
	// or already suspended device is left alone (false). ResumeDevice is the reverse and never
	// revives a revoked device. Both are conditional updates, so concurrent callers cannot both win.
	SuspendDevice(ctx context.Context, id models.ULID) (bool, error)
	ResumeDevice(ctx context.Context, id models.ULID) (bool, error)
	// DeviceBySPIFFEID and DeviceByKeyThumbprint are indexed lookups, ErrStorageNotFound on a miss.
	// The thumbprint is the RFC 7638 value in Device.KeyThumbprint. Two devices can share a key,
	// so the newest one is returned.
	DeviceBySPIFFEID(ctx context.Context, spiffeID string) (*models.Device, error)
	DeviceByKeyThumbprint(ctx context.Context, thumbprint string) (*models.Device, error)

	InsertDeviceJoinToken(ctx context.Context, t models.DeviceJoinToken) error
	DeviceJoinTokenByHash(ctx context.Context, hash []byte) (*models.DeviceJoinToken, error)
	DeviceJoinTokenByID(ctx context.Context, id models.ULID) (*models.DeviceJoinToken, error)
	RevokeDeviceJoinToken(ctx context.Context, id models.ULID, at time.Time) (bool, error)
	// RedeemDeviceJoinToken atomically marks an unredeemed, live token redeemed by deviceID. Exactly
	// one caller wins, which makes a join token single use.
	RedeemDeviceJoinToken(ctx context.Context, id, deviceID models.ULID, now time.Time) (bool, error)
	RefundDeviceJoinToken(ctx context.Context, id models.ULID) error
}
