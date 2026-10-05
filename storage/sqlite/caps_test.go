package sqlite_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storagetest"
)

func TestCapabilityContracts(t *testing.T) {
	t.Parallel()
	suites := []struct {
		name string
		run  func(t *testing.T, s *sqlitestore.Store)
	}{
		{"APITokens", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunAPITokens(t, s) }},
		{"DeviceCodes", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunDeviceCodes(t, s) }},
		{"SessionManagement", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunSessionManagement(t, s) }},
		{"MFACaps", func(t *testing.T, s *sqlitestore.Store) { storagetest.RunMFACaps(t, s) }},
	}
	for _, tc := range suites {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, newStore(t))
		})
		t.Run(tc.name+"CustomPrefix", func(t *testing.T) {
			t.Parallel()
			tc.run(t, newStore(t, sqlitestore.WithTablePrefix("auth_x_")))
		})
	}
}

func TestAdvanceTOTPStep(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	u := mkUser(t, s, "step@example.com")
	other := mkUser(t, s, "step2@example.com")

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

func TestCountUsers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	for want := 0; want < 3; want++ {
		got, err := s.CountUsers(ctx)
		if err != nil || got != want {
			t.Fatalf("CountUsers = %d, %v; want %d", got, err, want)
		}
		mkUser(t, s, "count"+string(rune('a'+want))+"@example.com")
	}
}

func TestSessionPersistsManagementFields(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	u := mkUser(t, s, "fields@example.com")
	seen := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	created, err := s.CreateSession(ctx, theauth.Session{
		ID: newID(), UserID: u.ID, TokenHash: []byte("h"), ExpiresAt: time.Now().Add(time.Hour),
		LastSeenAt: seen, CredentialID: "cred-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created.LastSeenAt.Equal(seen) || created.CredentialID != "cred-1" {
		t.Fatalf("created = %+v", created)
	}
	bare, err := s.CreateSession(ctx, theauth.Session{ID: newID(), UserID: u.ID, TokenHash: []byte("h2"), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if !bare.LastSeenAt.IsZero() {
		t.Fatalf("LastSeenAt = %v, want zero", bare.LastSeenAt)
	}
}

func TestThrottleStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t, sqlitestore.WithTablePrefix("tt_"))
	ts := s.ThrottleStore()
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

func TestThrottleConcurrentLimitersLoseNoFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	ts := s.ThrottleStore()
	bump := func() error {
		for {
			prev, ok, err := ts.Get(ctx, "mfa:user-1")
			if err != nil {
				return err
			}
			next := prev
			next.Failures++
			swapped, err := ts.CompareAndSwap(ctx, "mfa:user-1", prev, ok, next)
			if err != nil || swapped {
				return err
			}
		}
	}

	const perLimiter = 6
	const limiters = 2
	var wg sync.WaitGroup
	for i := 0; i < perLimiter*limiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := bump(); err != nil {
				t.Errorf("CompareAndSwap bump: %v", err)
			}
		}()
	}
	wg.Wait()
	e, ok, err := s.ThrottleStore().Get(ctx, "mfa:user-1")
	if err != nil || !ok {
		t.Fatalf("Get = %v, %v", ok, err)
	}
	if e.Failures != perLimiter*limiters {
		t.Fatalf("Failures = %d, want %d (lost updates)", e.Failures, perLimiter*limiters)
	}
}

func TestLegacyTokenImport(t *testing.T) {
	t.Parallel()
	storagetest.RunLegacyTokenImport(t, newStore(t))
}

func TestThrottleStoreDeleteLoginEntries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ts := newStore(t).ThrottleStore()
	e := theauth.LoginThrottleEntry{Failures: 1, ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
	keys := []string{"login:1.1.1.1|a_b@x.com", "login:2.2.2.2|a_b@x.com", "login:1.1.1.1|axb@x.com", "login:1.1.1.1|a%", "user:a_b@x.com"}
	for _, k := range keys {
		if err := ts.Set(ctx, k, e); err != nil {
			t.Fatal(err)
		}
	}
	del, ok := any(ts).(interface {
		DeleteLoginEntries(context.Context, string) error
	})
	if !ok {
		t.Fatal("ThrottleStore must implement DeleteLoginEntries")
	}
	if err := del.DeleteLoginEntries(ctx, "a_b@x.com"); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{keys[0]: false, keys[1]: false, keys[2]: true, keys[3]: true, keys[4]: true}
	for k, present := range want {
		if _, got, err := ts.Get(ctx, k); err != nil || got != present {
			t.Fatalf("key %q present=%v err=%v, want %v", k, got, err, present)
		}
	}
}
