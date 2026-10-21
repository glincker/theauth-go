package mqttauth

import (
	"context"
	"sync"
)

// PurgeBroadcaster carries a cache purge to every replica of the broker auth service. Purger and
// Handler.Purge act on one process only, so with several replicas a revoke would stay cached on
// the others until CacheTTL ran out. A broadcaster closes that gap: the replica that handled the
// revoke publishes, every replica (the publisher included) receives and drops its cached state.
//
// Delivery is best effort. A purge lost in transit is bounded by CacheTTL, exactly as without a
// broadcaster, and implementations that can notice a gap (a dropped connection) report it to the
// subscriber as a purge of everything, the empty device ID.
type PurgeBroadcaster interface {
	// Publish asks every subscriber to forget cached state for deviceID. An empty deviceID means
	// all cached state.
	Publish(ctx context.Context, deviceID string) error
	// Subscribe calls fn for each purge until ctx ends or the broadcaster fails for good, then
	// returns. fn must return quickly. An empty deviceID means purge everything.
	Subscribe(ctx context.Context, fn func(deviceID string)) error
}

// MemoryPurgeBroadcaster is an in process PurgeBroadcaster: Publish reaches every current
// subscriber of the same value. It is the single replica default and the test double for the
// shared implementations (storage/postgres has one over LISTEN and NOTIFY).
type MemoryPurgeBroadcaster struct {
	mu   sync.Mutex
	next int
	subs map[int]func(string)
}

var _ PurgeBroadcaster = (*MemoryPurgeBroadcaster)(nil)

// Publish implements PurgeBroadcaster. Subscribers run synchronously on the caller, so they must
// be quick, as the interface requires.
func (m *MemoryPurgeBroadcaster) Publish(_ context.Context, deviceID string) error {
	m.mu.Lock()
	fns := make([]func(string), 0, len(m.subs))
	for _, fn := range m.subs {
		fns = append(fns, fn)
	}
	m.mu.Unlock()
	for _, fn := range fns {
		fn(deviceID)
	}
	return nil
}

// Subscribe implements PurgeBroadcaster. It returns nil when ctx ends.
func (m *MemoryPurgeBroadcaster) Subscribe(ctx context.Context, fn func(deviceID string)) error {
	m.mu.Lock()
	if m.subs == nil {
		m.subs = map[int]func(string){}
	}
	id := m.next
	m.next++
	m.subs[id] = fn
	m.mu.Unlock()
	<-ctx.Done()
	m.mu.Lock()
	delete(m.subs, id)
	m.mu.Unlock()
	return nil
}
