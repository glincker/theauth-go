package throttle

import (
	"context"
	"sync"
	"time"
)

const defaultMaxEntries = 100000

// MemoryStore is the default in-process Store. Expired entries are swept
// lazily on writes, and the map is capped so unique identifiers sent by an
// attacker cannot grow it without bound.
type MemoryStore struct {
	mu         sync.Mutex
	entries    map[string]Entry
	maxEntries int
	sweepEvery time.Duration
	lastSweep  time.Time
	now        func() time.Time
}

// NewMemoryStore returns an empty store; maxEntries <= 0 selects the default cap.
func NewMemoryStore(maxEntries int) *MemoryStore {
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	return &MemoryStore{
		entries:    make(map[string]Entry),
		maxEntries: maxEntries,
		sweepEvery: time.Minute,
		now:        time.Now,
	}
}

// Get returns the entry for key. Expired entries may still be returned until
// swept; the Limiter ignores them.
func (m *MemoryStore) Get(_ context.Context, key string) (Entry, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	return e, ok, nil
}

// Set stores e under key, sweeping expired entries first when due.
func (m *MemoryStore) Set(_ context.Context, key string, e Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if now.Sub(m.lastSweep) >= m.sweepEvery || len(m.entries) >= m.maxEntries {
		m.sweepLocked(now)
	}
	if _, exists := m.entries[key]; !exists && len(m.entries) >= m.maxEntries {
		for k := range m.entries {
			delete(m.entries, k)
			break
		}
	}
	m.entries[key] = e
	return nil
}

// Delete removes key.
func (m *MemoryStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}

// Len reports the stored entry count, expired ones included until swept.
func (m *MemoryStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

func (m *MemoryStore) sweepLocked(now time.Time) {
	for k, e := range m.entries {
		if !e.ExpiresAt.After(now) {
			delete(m.entries, k)
		}
	}
	m.lastSweep = now
}
