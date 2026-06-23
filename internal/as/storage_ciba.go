package as

import (
	"context"
	"time"

	"github.com/glincker/theauth-go/internal/models"
)

// CIBAStorage is the persistence extension that storage backends must
// implement for CIBA to be active. When the Storage passed to as.New does
// not also satisfy CIBAStorage, the CIBA endpoints return 404 and the AS
// metadata omits the backchannel fields.
//
// Operators choosing not to implement CIBA simply leave these methods out of
// their storage adapter; the feature is auto-disabled.
type CIBAStorage interface {
	// InsertBackchannelRequest persists a new backchannel auth request.
	InsertBackchannelRequest(ctx context.Context, req models.BackchannelRequest) error

	// BackchannelRequestByID returns the request keyed by auth_req_id.
	// Returns ErrStorageNotFound when absent.
	BackchannelRequestByID(ctx context.Context, authReqID string) (models.BackchannelRequest, error)

	// UpdateBackchannelStatus writes a new status and, for approved requests,
	// the provisioned token strings. also updates LastPollAt and PollInterval
	// fields atomically.
	UpdateBackchannelRequest(ctx context.Context, req models.BackchannelRequest) error

	// DeleteBackchannelRequest removes the row. Used by operators that want
	// to purge completed flows; never called by the library automatically.
	DeleteBackchannelRequest(ctx context.Context, authReqID string) error

	// TouchBackchannelPoll records the current time as the last poll instant
	// and optionally widens PollInterval (for slow_down responses). Returns
	// the updated row so the service can read LastPollAt after the write.
	TouchBackchannelPoll(ctx context.Context, authReqID string, now time.Time, newInterval int) (models.BackchannelRequest, error)
}
