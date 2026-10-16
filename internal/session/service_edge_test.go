package session

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// nilSessionStore returns no row and no error, the case validate must survive.
type nilSessionStore struct{}

func (nilSessionStore) CreateSession(_ context.Context, s models.Session) (models.Session, error) {
	return s, nil
}

func (nilSessionStore) SessionByTokenHash(context.Context, []byte) (*models.Session, error) {
	return nil, nil
}

func (nilSessionStore) UserByID(context.Context, models.ULID) (*models.User, error) {
	return nil, models.ErrStorageNotFound
}

func TestValidateNilSessionFromStorageIsInvalidToken(t *testing.T) {
	svc := New(nilSessionStore{}, time.Hour)
	_, _, err := svc.Validate(context.Background(), "tok")
	if err != models.ErrInvalidToken {
		t.Fatalf("Validate = %v, want ErrInvalidToken", err)
	}
}

// TestValidateEmptyTokenEdge pins the empty-token and time boundary checks
// through the public Validate path without a storage round trip.
func TestValidateEmptyTokenEdge(t *testing.T) {
	svc := New(nilSessionStore{}, time.Hour)
	if _, _, err := svc.Validate(context.Background(), ""); err != models.ErrInvalidToken {
		t.Fatalf("empty token = %v, want ErrInvalidToken", err)
	}
}

// TestTouchGateSweepBoundsMemory checks that stale entries are pruned once
// the map is over the threshold and the sweep interval has elapsed, and that
// a sweep never drops an entry that is still inside the interval.
func TestTouchGateSweepBoundsMemory(t *testing.T) {
	var g touchGate
	interval := time.Minute
	t0 := time.Unix(1_900_000_000, 0)
	for i := 0; i <= touchGateSweepThreshold; i++ {
		if !g.allow(ulid.New(), t0, interval) {
			t.Fatalf("first allow for id %d returned false", i)
		}
	}
	// Every entry is fresh at t0, so nothing is stale and nothing is removed.
	if got := len(g.last); got != touchGateSweepThreshold+1 {
		t.Fatalf("fresh entries pruned: have %d", got)
	}
	later := t0.Add(interval + time.Second)
	fresh := ulid.New()
	if !g.allow(fresh, later, interval) {
		t.Fatal("allow for new id returned false")
	}
	if got := len(g.last); got != 1 {
		t.Fatalf("after sweep have %d entries, want only the fresh one", got)
	}
}

// TestTouchGateRateLimitsSweep checks the amortisation: a second sweep does
// not run inside the same interval, so stale entries added in that window
// survive until the interval has passed.
func TestTouchGateRateLimitsSweep(t *testing.T) {
	var g touchGate
	interval := time.Minute
	t0 := time.Unix(1_900_000_000, 0)
	for i := 0; i <= touchGateSweepThreshold; i++ {
		g.allow(ulid.New(), t0, interval)
	}
	t1 := t0.Add(interval + time.Second)
	g.allow(ulid.New(), t1, interval) // sweeps, sets swept = t1
	stale := t0.Add(-time.Hour)
	g.last[ulid.New()] = stale
	g.last[ulid.New()] = stale
	// Still inside the interval since the last sweep: no prune yet, although
	// the map is over the threshold again.
	for i := 0; i < touchGateSweepThreshold; i++ {
		g.allow(ulid.New(), t1.Add(time.Second), interval)
	}
	stalePresent := 0
	for _, ts := range g.last {
		if ts.Equal(stale) {
			stalePresent++
		}
	}
	if stalePresent != 2 {
		t.Fatalf("stale entries inside the sweep interval: have %d, want 2 kept", stalePresent)
	}
	g.allow(ulid.New(), t1.Add(interval+time.Second), interval)
	for _, ts := range g.last {
		if ts.Equal(stale) {
			t.Fatal("stale entry survived a sweep after the interval elapsed")
		}
	}
}
