package postgres

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/throttle"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storagetest"
)

func capsStore(t *testing.T) *Store {
	t.Helper()
	pool := testPool(t)
	t.Cleanup(pool.Close)
	return New(pool)
}

func mkCapsUser(t *testing.T, s *Store, email string) theauth.User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), theauth.User{ID: ulid.New(), Email: email, CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestPostgresCapabilityContracts(t *testing.T) {
	suites := []struct {
		name string
		run  func(t *testing.T, s *Store)
	}{
		{"APITokens", func(t *testing.T, s *Store) { storagetest.RunAPITokens(t, s) }},
		{"DeviceCodes", func(t *testing.T, s *Store) { storagetest.RunDeviceCodes(t, s) }},
		{"DeviceAuthorizations", func(t *testing.T, s *Store) { storagetest.RunDeviceAuthorizations(t, s) }},
		{"RegistrationTokens", func(t *testing.T, s *Store) { storagetest.RunRegistrationTokens(t, s) }},
		{"OpaqueTokens", func(t *testing.T, s *Store) { storagetest.RunOpaqueTokens(t, s) }},
		{"SessionManagement", func(t *testing.T, s *Store) { storagetest.RunSessionManagement(t, s) }},
	}
	for _, tc := range suites {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, capsStore(t)) })
	}
}

func TestPostgresAdvanceTOTPStep(t *testing.T) {
	ctx := context.Background()
	s := capsStore(t)
	u := mkCapsUser(t, s, "step@example.com")
	other := mkCapsUser(t, s, "step2@example.com")

	steps := []struct {
		user theauth.ULID
		step int64
		want bool
	}{
		{u.ID, 10, true}, {u.ID, 10, false}, {u.ID, 9, false}, {u.ID, 11, true}, {other.ID, 5, true},
	}
	for i, tc := range steps {
		got, err := s.AdvanceTOTPStep(ctx, tc.user, tc.step)
		if err != nil || got != tc.want {
			t.Fatalf("case %d: AdvanceTOTPStep = %v, %v; want %v", i, got, err, tc.want)
		}
	}

	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := s.AdvanceTOTPStep(ctx, u.ID, 500); err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("concurrent winners = %d, want 1", wins.Load())
	}
}

func TestPostgresCountUsers(t *testing.T) {
	ctx := context.Background()
	s := capsStore(t)
	for want := 0; want < 3; want++ {
		got, err := s.CountUsers(ctx)
		if err != nil || got != want {
			t.Fatalf("CountUsers = %d, %v; want %d", got, err, want)
		}
		mkCapsUser(t, s, "count"+string(rune('a'+want))+"@example.com")
	}
}

func TestPostgresSessionPersistsManagementFields(t *testing.T) {
	ctx := context.Background()
	s := capsStore(t)
	u := mkCapsUser(t, s, "fields@example.com")
	seen := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	created, err := s.CreateSession(ctx, theauth.Session{
		ID: ulid.New(), UserID: u.ID, TokenHash: []byte("h"), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		LastSeenAt: seen, CredentialID: "cred-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created.LastSeenAt.Equal(seen) || created.CredentialID != "cred-1" {
		t.Fatalf("created = %+v", created)
	}
	bare, err := s.CreateSession(ctx, theauth.Session{ID: ulid.New(), UserID: u.ID, TokenHash: []byte("h2"), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if !bare.LastSeenAt.IsZero() {
		t.Fatalf("LastSeenAt = %v, want zero", bare.LastSeenAt)
	}
}

func TestPostgresThrottleStore(t *testing.T) {
	ctx := context.Background()
	ts := capsStore(t).ThrottleStore()
	now := time.Now().UTC().Truncate(time.Microsecond)

	if _, ok, err := ts.Get(ctx, "k"); err != nil || ok {
		t.Fatalf("Get missing = %v, %v", ok, err)
	}
	e1 := theauth.LoginThrottleEntry{Failures: 1, LastFailure: now, ExpiresAt: now.Add(time.Minute)}
	e2 := theauth.LoginThrottleEntry{Failures: 2, LastFailure: now, BlockedUntil: now.Add(time.Second), ExpiresAt: now.Add(time.Minute)}

	steps := []struct {
		name       string
		prev       theauth.LoginThrottleEntry
		prevExists bool
		next       theauth.LoginThrottleEntry
		want       bool
	}{
		{"insert when absent", theauth.LoginThrottleEntry{}, false, e1, true},
		{"insert loses when present", theauth.LoginThrottleEntry{}, false, e2, false},
		{"stale prev loses", e2, true, e2, false},
		{"matching prev wins", e1, true, e2, true},
		{"old prev now stale", e1, true, e2, false},
	}
	for _, tc := range steps {
		got, err := ts.CompareAndSwap(ctx, "k", tc.prev, tc.prevExists, tc.next)
		if err != nil || got != tc.want {
			t.Fatalf("%s: = %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	got, ok, err := ts.Get(ctx, "k")
	if err != nil || !ok || got.Failures != 2 || !got.BlockedUntil.Equal(e2.BlockedUntil) || !got.ExpiresAt.Equal(e2.ExpiresAt) {
		t.Fatalf("Get = %+v, %v, %v", got, ok, err)
	}
	if n, err := ts.SweepExpired(ctx, now.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("SweepExpired = %d, %v", n, err)
	}
	if err := ts.Set(ctx, "k", e1); err != nil {
		t.Fatal(err)
	}
	if err := ts.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := ts.Get(ctx, "k"); ok {
		t.Fatal("entry survived Delete")
	}
}

func TestPostgresThrottleConcurrentLimitersLoseNoFailures(t *testing.T) {
	ctx := context.Background()
	s := capsStore(t)
	cfg := throttle.Config{MFAMaxFailures: 1_000_000}
	limiters := []*throttle.Limiter{throttle.New(s.ThrottleStore(), cfg), throttle.New(s.ThrottleStore(), cfg)}

	const perLimiter = 6
	var wg sync.WaitGroup
	for _, l := range limiters {
		for i := 0; i < perLimiter; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := l.RecordMFAFailure(ctx, "user-1"); err != nil {
					t.Errorf("RecordMFAFailure: %v", err)
				}
			}()
		}
	}
	wg.Wait()
	e, ok, err := s.ThrottleStore().Get(ctx, "mfa:user-1")
	if err != nil || !ok {
		t.Fatalf("Get = %v, %v", ok, err)
	}
	if e.Failures != perLimiter*len(limiters) {
		t.Fatalf("Failures = %d, want %d (lost updates)", e.Failures, perLimiter*len(limiters))
	}
}
