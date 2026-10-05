package oauth

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrStateNotFound is returned by StateStore.Take when the key is unknown,
// already consumed, or expired.
var ErrStateNotFound = errors.New("theauth: oauth state not found")

// State is the per-flow record stored between /start and /callback.
type State struct {
	Provider     string
	CodeVerifier string
	RedirectURI  string
	// Nonce is the OIDC nonce, empty for providers that do not use one.
	Nonce string
	// ReturnTo is the validated post-login destination, empty for the default.
	ReturnTo string
	// BindingHash is SHA-256 of the browser binding cookie value.
	BindingHash []byte
	CreatedAt   time.Time
}

// StateStore holds State between /start and /callback. Take must be atomic
// and single use: a second Take of the same key returns ErrStateNotFound.
type StateStore interface {
	Put(ctx context.Context, key string, st State, ttl time.Duration) error
	Take(ctx context.Context, key string) (State, error)
}

type memEntry struct {
	st      State
	expires time.Time
}

// MemoryStateStore is the default in-process StateStore.
type MemoryStateStore struct {
	mu      sync.Mutex
	entries map[string]memEntry
	stop    chan struct{}
	once    sync.Once
}

// NewMemoryStateStore returns a MemoryStateStore that sweeps expired
// entries every minute until Close is called.
func NewMemoryStateStore() *MemoryStateStore {
	m := &MemoryStateStore{entries: map[string]memEntry{}, stop: make(chan struct{})}
	go m.sweepLoop(time.Minute)
	return m
}

// Put stores st under key for ttl.
func (m *MemoryStateStore) Put(_ context.Context, key string, st State, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = memEntry{st: st, expires: time.Now().Add(ttl)}
	return nil
}

// Take removes and returns the entry for key.
func (m *MemoryStateStore) Take(_ context.Context, key string) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok {
		return State{}, ErrStateNotFound
	}
	delete(m.entries, key)
	if time.Now().After(e.expires) {
		return State{}, ErrStateNotFound
	}
	return e.st, nil
}

// Len reports the number of stored entries, expired ones included until swept.
func (m *MemoryStateStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// Sweep drops expired entries now.
func (m *MemoryStateStore) Sweep() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, e := range m.entries {
		if now.After(e.expires) {
			delete(m.entries, k)
		}
	}
}

// Close stops the background sweeper. Safe to call more than once.
func (m *MemoryStateStore) Close() { m.once.Do(func() { close(m.stop) }) }

func (m *MemoryStateStore) sweepLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.Sweep()
		}
	}
}
