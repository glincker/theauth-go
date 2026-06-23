package theauth

import (
	"context"
	"time"
)

// CIBAStorage is the optional persistence extension that storage backends must
// implement for CIBA to be active. When the storage passed to New does not
// also satisfy CIBAStorage, the /oauth/bc-authorize endpoint is not mounted
// and the AS metadata does not advertise CIBA fields.
//
// Memory and Postgres adapters in storage/memory and storage/postgres both
// implement CIBAStorage. Custom adapters only need to add these five methods
// before enabling Config.AuthorizationServer.CIBA.
type CIBAStorage interface {
	// InsertBackchannelRequest persists a new backchannel auth request.
	InsertBackchannelRequest(ctx context.Context, req BackchannelRequest) error

	// BackchannelRequestByID returns the request keyed by auth_req_id.
	// Returns ErrStorageNotFound when absent.
	BackchannelRequestByID(ctx context.Context, authReqID string) (BackchannelRequest, error)

	// UpdateBackchannelRequest writes status changes and the approved token
	// strings atomically.
	UpdateBackchannelRequest(ctx context.Context, req BackchannelRequest) error

	// DeleteBackchannelRequest removes the row. The library never calls this
	// automatically; operators call it for housekeeping.
	DeleteBackchannelRequest(ctx context.Context, authReqID string) error

	// TouchBackchannelPoll records the current time as the last poll instant
	// and stores a new poll interval, then returns the updated row.
	TouchBackchannelPoll(ctx context.Context, authReqID string, now time.Time, newInterval int) (BackchannelRequest, error)
}
