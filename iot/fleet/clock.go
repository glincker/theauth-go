package fleet

import (
	"sync"
	"time"
)

// DefaultStart is where a new VirtualClock starts: midnight UTC on 2030-01-01, far from any real run.
var DefaultStart = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

// VirtualClock is the only time source of the server side during a run: it is the Clock of the
// authorization server, so token and bundle lifetimes, replay windows and challenge expiry all read it.
// Runs are repeatable and a test can move a day forward in one call. It implements theauth.Clock.
type VirtualClock struct {
	mu  sync.RWMutex
	now time.Time
}

// NewVirtualClock starts at start, DefaultStart when zero.
func NewVirtualClock(start time.Time) *VirtualClock {
	if start.IsZero() {
		start = DefaultStart
	}
	return &VirtualClock{now: start}
}

// Now returns the virtual time.
func (c *VirtualClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

// Advance moves the clock forward by d. A negative d is ignored: time only moves forward.
func (c *VirtualClock) Advance(d time.Duration) {
	if d <= 0 {
		return
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}
