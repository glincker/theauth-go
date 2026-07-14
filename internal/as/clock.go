package as

import "time"

// Clock is the time source used by the introspection cache and the
// chain-cache TTL. Config.Validate defaults this to realClock when nil, so
// production behavior is unchanged; tests inject a fake clock to assert
// revocation propagation deterministically instead of sleeping past the
// cache TTL.
type Clock interface {
	Now() time.Time
}

// realClock is the production Clock, a thin wrapper around time.Now.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
