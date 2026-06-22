package memory

import (
	"context"
	"sync"
	"time"

	"github.com/glincker/theauth-go/storage"
)

// jtiState backs the in-process JTI replay cache. A single global sync.Map
// would work too but keeping it on the Store struct makes tests that spin
// multiple Store instances properly isolated.
type jtiState struct {
	mu   sync.Mutex
	jtis map[string]time.Time // jti -> expiresAt
}

func (s *Store) ensureJTI() *jtiState {
	if s.jti == nil {
		s.jti = &jtiState{jtis: map[string]time.Time{}}
	}
	return s.jti
}

// InsertJTI records a new JTI. Returns storage.ErrNotFound when the JTI
// already exists within its expiry window (reusing the "not found" sentinel
// as the "duplicate detected" signal per the JWTBearerStorage contract).
func (s *Store) InsertJTI(_ context.Context, jti string, expiresAt time.Time) error {
	j := s.ensureJTI()
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	// Sweep expired entries on every insert to keep memory bounded.
	for k, exp := range j.jtis {
		if exp.Before(now) {
			delete(j.jtis, k)
		}
	}
	if _, exists := j.jtis[jti]; exists {
		return storage.ErrNotFound // duplicate = replay detected
	}
	j.jtis[jti] = expiresAt
	return nil
}

// SweepExpiredJTIs removes all entries whose expiresAt is before the
// supplied time.
func (s *Store) SweepExpiredJTIs(_ context.Context, before time.Time) error {
	j := s.ensureJTI()
	j.mu.Lock()
	defer j.mu.Unlock()
	for k, exp := range j.jtis {
		if exp.Before(before) {
			delete(j.jtis, k)
		}
	}
	return nil
}
