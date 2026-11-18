package device

import (
	"sync"
	"time"
)

// SyncedClock gives a device without a battery backed RTC a usable "now".
//
// Such a device boots at an arbitrary time, so it cannot judge exp or nbf on its own.
// The fix is to anchor to a time that something trustworthy just told it (the iat of a
// freshly verified bundle, or the Date header of a TLS response) and then add elapsed
// time from a monotonic tick counter, which every MCU has. Until the first sync Now
// reports false and callers must deny.
//
// Two rules keep this safe. The anchor only moves forward, so replaying an older signed
// bundle cannot drag the clock back and revive an expired one. And the elapsed time comes
// from Elapsed, not from a wall clock the attacker could set.
type SyncedClock struct {
	mu      sync.Mutex
	elapsed func() time.Duration
	anchor  time.Time
	atTick  time.Duration
	synced  bool
}

// NewSyncedClock takes a monotonic counter, for example time.Since of a start instant
// or a hardware tick converted to a Duration. It must never go backwards.
func NewSyncedClock(elapsed func() time.Duration) *SyncedClock {
	return &SyncedClock{elapsed: elapsed}
}

// Sync records an authenticated server time. It returns false and changes nothing when
// t is more than 30 s behind the current estimate, which is how a stale replay is ignored.
// A smaller step back is accepted so ordinary drift can be corrected.
func (c *SyncedClock) Sync(t time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.synced && t.Before(c.nowLocked().Add(-skewSeconds*time.Second)) {
		return false
	}
	c.anchor, c.atTick, c.synced = t, c.elapsed(), true
	return true
}

func (c *SyncedClock) nowLocked() time.Time { return c.anchor.Add(c.elapsed() - c.atTick) }

// Now returns the estimate, and false before the first Sync.
func (c *SyncedClock) Now() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.synced {
		return time.Time{}, false
	}
	return c.nowLocked(), true
}
