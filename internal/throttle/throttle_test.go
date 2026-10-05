package throttle

import (
	"context"
	"errors"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTest(cfg Config) (*Limiter, *clock, *MemoryStore) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	st := NewMemoryStore(0)
	st.now = c.now
	l := New(st, cfg)
	l.SetClock(c.now)
	return l, c, st
}

func TestLoginBackoffAfterGrace(t *testing.T) {
	ctx := context.Background()
	l, c, _ := newTest(Config{GraceFailures: 2, BaseDelay: time.Second, MaxDelay: 8 * time.Second, UserMaxFailures: 1000})
	const ip, id = "1.2.3.4", "a@b.c"

	for i := 0; i < 2; i++ {
		if err := l.CheckLogin(ctx, ip, id); err != nil {
			t.Fatalf("attempt %d inside grace blocked: %v", i, err)
		}
		if err := l.RecordLoginFailure(ctx, ip, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.CheckLogin(ctx, ip, id); err != nil {
		t.Fatalf("grace boundary blocked: %v", err)
	}

	wantDelays := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second}
	for i, want := range wantDelays {
		if err := l.RecordLoginFailure(ctx, ip, id); err != nil {
			t.Fatal(err)
		}
		var be *BlockedError
		err := l.CheckLogin(ctx, ip, id)
		if !errors.As(err, &be) {
			t.Fatalf("step %d: want BlockedError, got %v", i, err)
		}
		if be.RetryAfter != want || be.Locked {
			t.Fatalf("step %d: retry %v locked %v, want %v unlocked", i, be.RetryAfter, be.Locked, want)
		}
		c.advance(want)
		if err := l.CheckLogin(ctx, ip, id); err != nil {
			t.Fatalf("step %d: still blocked after delay: %v", i, err)
		}
	}
}

func TestLoginKeyedPerIPAndIdentifier(t *testing.T) {
	ctx := context.Background()
	l, _, _ := newTest(Config{GraceFailures: 1, UserMaxFailures: 1000})
	for i := 0; i < 3; i++ {
		_ = l.RecordLoginFailure(ctx, "1.1.1.1", "a@b.c")
	}
	tests := []struct {
		name, ip, id string
		blocked      bool
	}{
		{"same pair", "1.1.1.1", "a@b.c", true},
		{"other ip", "2.2.2.2", "a@b.c", false},
		{"other identifier", "1.1.1.1", "x@y.z", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := l.CheckLogin(ctx, tc.ip, tc.id) != nil; got != tc.blocked {
				t.Fatalf("blocked=%v want %v", got, tc.blocked)
			}
		})
	}
}

func TestUserLockoutAcrossIPsExpiresAndUnlocks(t *testing.T) {
	ctx := context.Background()
	l, c, _ := newTest(Config{GraceFailures: 1000, UserMaxFailures: 3, UserLockout: time.Hour})
	for i := 0; i < 3; i++ {
		_ = l.RecordLoginFailure(ctx, "10.0.0."+string(rune('1'+i)), "victim@x.y")
	}
	var be *BlockedError
	if err := l.CheckLogin(ctx, "9.9.9.9", "victim@x.y"); !errors.As(err, &be) || !be.Locked {
		t.Fatalf("want lockout from a fresh ip, got %v", err)
	}
	c.advance(time.Hour + time.Second)
	if err := l.CheckLogin(ctx, "9.9.9.9", "victim@x.y"); err != nil {
		t.Fatalf("lockout did not auto-expire: %v", err)
	}
	_ = l.RecordLoginFailure(ctx, "9.9.9.9", "victim@x.y")
	if err := l.CheckLogin(ctx, "9.9.9.9", "victim@x.y"); err != nil {
		t.Fatalf("single failure after expiry re-locked: %v", err)
	}
	for i := 0; i < 3; i++ {
		_ = l.RecordLoginFailure(ctx, "9.9.9.9", "victim@x.y")
	}
	if err := l.CheckLogin(ctx, "8.8.8.8", "victim@x.y"); err == nil {
		t.Fatal("expected lockout")
	}
	if err := l.UnlockIdentifier(ctx, "victim@x.y", ""); err != nil {
		t.Fatal(err)
	}
	if err := l.CheckLogin(ctx, "8.8.8.8", "victim@x.y"); err != nil {
		t.Fatalf("admin unlock failed: %v", err)
	}
}

func TestSuccessResetsCounters(t *testing.T) {
	ctx := context.Background()
	l, _, _ := newTest(Config{GraceFailures: 1, UserMaxFailures: 1000})
	_ = l.RecordLoginFailure(ctx, "1.1.1.1", "a@b.c")
	_ = l.RecordLoginFailure(ctx, "1.1.1.1", "a@b.c")
	if err := l.RecordLoginSuccess(ctx, "1.1.1.1", "a@b.c"); err != nil {
		t.Fatal(err)
	}
	if err := l.CheckLogin(ctx, "1.1.1.1", "a@b.c"); err != nil {
		t.Fatalf("blocked after success: %v", err)
	}
}

func TestMFALockoutIsPerUser(t *testing.T) {
	ctx := context.Background()
	l, c, _ := newTest(Config{MFAMaxFailures: 3, MFALockout: 10 * time.Minute})
	for i := 0; i < 3; i++ {
		if err := l.CheckMFA(ctx, "u1"); err != nil {
			t.Fatalf("blocked early at %d: %v", i, err)
		}
		_ = l.RecordMFAFailure(ctx, "u1")
	}
	if err := l.CheckMFA(ctx, "u1"); err == nil {
		t.Fatal("expected mfa lockout")
	}
	if err := l.CheckMFA(ctx, "u2"); err != nil {
		t.Fatalf("other user affected: %v", err)
	}
	c.advance(11 * time.Minute)
	if err := l.CheckMFA(ctx, "u1"); err != nil {
		t.Fatalf("mfa lockout did not expire: %v", err)
	}
}

func TestMemoryStoreSweepsExpiredAndCaps(t *testing.T) {
	ctx := context.Background()
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	st := NewMemoryStore(5)
	st.now = c.now
	for i := 0; i < 4; i++ {
		_ = st.Set(ctx, "k"+string(rune('a'+i)), Entry{ExpiresAt: c.t.Add(time.Minute)})
	}
	c.advance(2 * time.Minute)
	_ = st.Set(ctx, "fresh", Entry{ExpiresAt: c.t.Add(time.Minute)})
	if got := st.Len(); got != 1 {
		t.Fatalf("expired entries not swept, len=%d", got)
	}
	for i := 0; i < 20; i++ {
		_ = st.Set(ctx, "n"+string(rune('a'+i)), Entry{ExpiresAt: c.t.Add(time.Hour)})
	}
	if got := st.Len(); got > 5 {
		t.Fatalf("cap exceeded, len=%d", got)
	}
}

func TestMemoryStoreCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore(0)
	e1, e2 := Entry{Failures: 1}, Entry{Failures: 2}
	tests := []struct {
		name       string
		prev       Entry
		prevExists bool
		next       Entry
		want       bool
	}{
		{"insert when absent", Entry{}, false, e1, true},
		{"insert loses when present", Entry{}, false, e2, false},
		{"stale prev loses", e2, true, e2, false},
		{"matching prev wins", e1, true, e2, true},
	}
	for _, tc := range tests {
		got, err := st.CompareAndSwap(ctx, "k", tc.prev, tc.prevExists, tc.next)
		if err != nil || got != tc.want {
			t.Fatalf("%s: = %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
}

type plainStore struct{ Store }

func TestClearLoginBackoff(t *testing.T) {
	ctx := context.Background()
	cfg := Config{GraceFailures: 1, BaseDelay: time.Hour, MaxDelay: time.Hour, UserMaxFailures: 1000}
	tests := []struct {
		name      string
		supported bool
		wantFree  bool
	}{
		{"store with deleter clears every ip", true, true},
		{"store without deleter is a no-op", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, _, st := newTest(cfg)
			if !tc.supported {
				l.store = plainStore{st}
			}
			for _, ip := range []string{"1.1.1.1", "2.2.2.2"} {
				for i := 0; i < 3; i++ {
					_ = l.RecordLoginFailure(ctx, ip, "a@b.c")
				}
			}
			_ = l.RecordLoginFailure(ctx, "1.1.1.1", "other@b.c")
			if err := l.ClearLoginBackoff(ctx, "a@b.c"); err != nil {
				t.Fatal(err)
			}
			for _, ip := range []string{"1.1.1.1", "2.2.2.2"} {
				if got := l.CheckLogin(ctx, ip, "a@b.c") == nil; got != tc.wantFree {
					t.Fatalf("ip %s free=%v want %v", ip, got, tc.wantFree)
				}
			}
			if _, ok, _ := st.Get(ctx, loginKey("1.1.1.1", "other@b.c")); !ok {
				t.Fatal("other identifier entry must be kept")
			}
		})
	}
}
