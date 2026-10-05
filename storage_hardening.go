package theauth

import "context"

// TOTPReplayStorage is an optional capability that makes TOTP replay
// protection durable and shared across processes. Without it the library
// tracks the last used step in process memory only.
type TOTPReplayStorage interface {
	// AdvanceTOTPStep atomically records step as the user's last used TOTP
	// time-step. It returns false, and changes nothing, when step is not
	// strictly greater than the stored value (a replayed or older code).
	AdvanceTOTPStep(ctx context.Context, userID ULID, step int64) (advanced bool, err error)
}

// UserCountStorage is an optional capability required by Config.Bootstrap
// to detect whether the first administrator has been created yet.
type UserCountStorage interface {
	// CountUsers returns the total number of user records.
	CountUsers(ctx context.Context) (int, error)
}
