package as

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// DeviceAuthorizationStorage is the persistence extension for the RFC 8628 device grant. Without it
// the device endpoints stay unmounted. Decide and consume are conditional updates that report
// whether they applied, so concurrent callers cannot both win.
type DeviceAuthorizationStorage interface {
	// InsertDeviceAuthorization stores a pending record. It returns ErrDeviceAuthUserCodeTaken when
	// the user code hash collides with a live record.
	InsertDeviceAuthorization(ctx context.Context, d models.DeviceAuthorization) error

	DeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash []byte) (*models.DeviceAuthorization, error)

	DeviceAuthorizationByUserCodeHash(ctx context.Context, hash []byte) (*models.DeviceAuthorization, error)

	// DecideDeviceAuthorization moves a pending, unexpired record to approved or denied. It reports
	// false when the record was not pending.
	DecideDeviceAuthorization(ctx context.Context, id models.ULID, status string, userID models.ULID, now time.Time) (bool, error)

	// RecordDeviceAuthorizationPoll stores the poll time and the possibly widened interval for
	// slow_down accounting.
	RecordDeviceAuthorizationPoll(ctx context.Context, id models.ULID, polledAt time.Time, intervalSeconds int) error

	// ConsumeDeviceAuthorization atomically moves an approved record to consumed. Exactly one caller
	// gets true, which makes a device code single use.
	ConsumeDeviceAuthorization(ctx context.Context, id models.ULID, now time.Time) (bool, error)

	DeleteExpiredDeviceAuthorizations(ctx context.Context, before time.Time) (int64, error)
}

// RegistrationTokenStorage is the persistence extension for initial access tokens. Without it only
// Config.RegistrationTokens works.
type RegistrationTokenStorage interface {
	InsertRegistrationToken(ctx context.Context, t models.RegistrationToken) error

	RegistrationTokenByHash(ctx context.Context, hash []byte) (*models.RegistrationToken, error)

	RegistrationTokenByID(ctx context.Context, id models.ULID) (*models.RegistrationToken, error)

	ListRegistrationTokens(ctx context.Context, orgID *models.ULID) ([]models.RegistrationToken, error)

	RevokeRegistrationToken(ctx context.Context, id models.ULID, at time.Time) (bool, error)

	// RedeemRegistrationToken atomically spends one use when the token is live and under MaxUses, and
	// reports whether it did.
	RedeemRegistrationToken(ctx context.Context, id models.ULID, now time.Time) (bool, error)

	RefundRegistrationToken(ctx context.Context, id models.ULID) error
}
