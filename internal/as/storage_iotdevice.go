package as

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// DeviceIdentityStorage is the persistence extension for registered
// constrained devices and their join tokens. When the Storage passed to as.New
// does not implement it, Config.DeviceTokens is rejected at startup.
//
// Lookups return models.ErrStorageNotFound on a miss. Redeem and revoke are
// conditional updates that report whether they applied, so concurrent callers
// cannot both win.
type DeviceIdentityStorage interface {
	// InsertDevice stores a device. It returns models.ErrDeviceConflict when
	// the SPIFFE ID is already registered.
	InsertDevice(ctx context.Context, d models.Device) error
	DeviceByID(ctx context.Context, id models.ULID) (*models.Device, error)
	// ListDevices returns devices newest first. A nil orgID lists every device.
	ListDevices(ctx context.Context, orgID *models.ULID) ([]models.Device, error)
	// RevokeDevice marks an active device revoked and reports whether it
	// changed anything.
	RevokeDevice(ctx context.Context, id models.ULID, at time.Time) (bool, error)
	// TouchDevice stamps last_seen_at.
	TouchDevice(ctx context.Context, id models.ULID, at time.Time) error

	InsertDeviceJoinToken(ctx context.Context, t models.DeviceJoinToken) error
	DeviceJoinTokenByHash(ctx context.Context, hash []byte) (*models.DeviceJoinToken, error)
	DeviceJoinTokenByID(ctx context.Context, id models.ULID) (*models.DeviceJoinToken, error)
	// RevokeDeviceJoinToken revokes a token that is not yet revoked.
	RevokeDeviceJoinToken(ctx context.Context, id models.ULID, at time.Time) (bool, error)
	// RedeemDeviceJoinToken atomically marks an unredeemed, unrevoked,
	// unexpired token redeemed by deviceID and reports whether this call did
	// it. Exactly one caller wins, which makes a join token single use.
	RedeemDeviceJoinToken(ctx context.Context, id, deviceID models.ULID, now time.Time) (bool, error)
	// RefundDeviceJoinToken undoes a redemption when enrollment failed after it.
	RefundDeviceJoinToken(ctx context.Context, id models.ULID) error
}
