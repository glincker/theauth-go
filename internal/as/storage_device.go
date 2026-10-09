package as

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// DeviceAuthorizationStorage is the persistence extension for the RFC 8628
// device grant. When the Storage passed to as.New does not implement it, the
// device endpoints stay unmounted and the AS metadata omits them.
//
// Lookups return models.ErrStorageNotFound on a miss. All mutations that gate
// a security decision (decide, consume) are conditional updates that report
// whether they applied, so concurrent callers cannot both win.
type DeviceAuthorizationStorage interface {
	// InsertDeviceAuthorization stores a new pending record. It returns
	// models.ErrDeviceAuthUserCodeTaken when the user code hash collides
	// with a record that has not yet expired.
	InsertDeviceAuthorization(ctx context.Context, d models.DeviceAuthorization) error

	// DeviceAuthorizationByDeviceCodeHash looks a record up by device code.
	DeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash []byte) (*models.DeviceAuthorization, error)

	// DeviceAuthorizationByUserCodeHash looks a record up by user code.
	DeviceAuthorizationByUserCodeHash(ctx context.Context, hash []byte) (*models.DeviceAuthorization, error)

	// DecideDeviceAuthorization moves a pending, unexpired record to status
	// (approved or denied) and records the deciding user. It reports false
	// when the record was not pending or had expired.
	DecideDeviceAuthorization(ctx context.Context, id models.ULID, status string, userID models.ULID, now time.Time) (bool, error)

	// RecordDeviceAuthorizationPoll stores the poll time and the (possibly widened)
	// interval for slow_down accounting.
	RecordDeviceAuthorizationPoll(ctx context.Context, id models.ULID, polledAt time.Time, intervalSeconds int) error

	// ConsumeDeviceAuthorization atomically moves an approved record to
	// consumed and reports whether this call did it. Exactly one caller
	// gets true, which is what makes a device code single use.
	ConsumeDeviceAuthorization(ctx context.Context, id models.ULID, now time.Time) (bool, error)

	// DeleteExpiredDeviceAuthorizations removes rows that expired before the
	// cutoff and returns how many it deleted. Housekeeping only.
	DeleteExpiredDeviceAuthorizations(ctx context.Context, before time.Time) (int64, error)
}

// RegistrationTokenStorage is the persistence extension for initial access
// tokens. When absent only the static Config.RegistrationTokens list works.
type RegistrationTokenStorage interface {
	InsertRegistrationToken(ctx context.Context, t models.RegistrationToken) error

	// RegistrationTokenByHash returns models.ErrStorageNotFound on a miss.
	RegistrationTokenByHash(ctx context.Context, hash []byte) (*models.RegistrationToken, error)

	// RegistrationTokenByID returns models.ErrStorageNotFound on a miss.
	RegistrationTokenByID(ctx context.Context, id models.ULID) (*models.RegistrationToken, error)

	// ListRegistrationTokens returns tokens newest first. A nil orgID lists
	// every token; otherwise only that organization's.
	ListRegistrationTokens(ctx context.Context, orgID *models.ULID) ([]models.RegistrationToken, error)

	// RevokeRegistrationToken sets revoked_at on a token that is not yet
	// revoked and reports whether it changed anything.
	RevokeRegistrationToken(ctx context.Context, id models.ULID, at time.Time) (bool, error)

	// RedeemRegistrationToken atomically increments uses when the token is
	// unrevoked, unexpired at now and uses < max_uses, and reports whether
	// it did. It also stamps last_used_at.
	RedeemRegistrationToken(ctx context.Context, id models.ULID, now time.Time) (bool, error)

	// RefundRegistrationToken undoes one redemption (uses - 1, floor 0) when
	// the registration that consumed it failed.
	RefundRegistrationToken(ctx context.Context, id models.ULID) error
}
