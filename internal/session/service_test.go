package session_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/session"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func TestDeviceLabel(t *testing.T) {
	tests := []struct{ name, ua, want string }{
		{"empty", "", "Unknown device"},
		{"blank", "   ", "Unknown device"},
		{"chrome mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0 Safari/537.36", "Chrome on macOS"},
		{"edge windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36 Edg/126.0", "Edge on Windows"},
		{"firefox linux", "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0", "Firefox on Linux"},
		{"safari ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1", "Safari on iOS"},
		{"chrome android", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36", "Chrome on Android"},
		{"curl", "curl/8.4.0", "curl"},
		{"os only", "SomeAgent (Windows)", "Windows"},
		{"garbage", "zzz", "Unknown device"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := session.DeviceLabel(tc.ua); got != tc.want {
				t.Fatalf("DeviceLabel(%q) = %q, want %q", tc.ua, got, tc.want)
			}
		})
	}
}

func TestIPPrefix(t *testing.T) {
	tests := []struct{ in, want string }{
		{"203.0.113.77", "203.0.113.0/24"},
		{"203.0.113.77:51234", "203.0.113.0/24"},
		{"::ffff:198.51.100.9", "198.51.100.0/24"},
		{"2001:db8:abcd:12::1", "2001:db8:abcd::/48"},
		{"[2001:db8:abcd:12::1]:443", "2001:db8:abcd::/48"},
		{"", ""},
		{"not-an-ip", ""},
	}
	for _, tc := range tests {
		if got := session.IPPrefix(tc.in); got != tc.want {
			t.Errorf("IPPrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

type countingToucher struct {
	store *memory.Store
	n     atomic.Int64
}

func (c *countingToucher) TouchSession(ctx context.Context, id models.ULID, at time.Time) error {
	c.n.Add(1)
	return c.store.TouchSession(ctx, id, at)
}

type revokeRecorder struct {
	store   *memory.Store
	revoked atomic.Int64
}

func (r *revokeRecorder) RevokeSession(ctx context.Context, id models.ULID) error {
	r.revoked.Add(1)
	return r.store.RevokeSession(ctx, id)
}

func setup(t *testing.T) (*session.Service, *memory.Store, models.User) {
	t.Helper()
	store := memory.New()
	u, err := store.CreateUser(context.Background(), models.User{ID: ulid.New(), Email: "u@x.test", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return session.New(store, time.Hour), store, u
}

func TestConcurrentValidateThrottlesLastSeenWrites(t *testing.T) {
	svc, store, user := setup(t)
	toucher := &countingToucher{store: store}
	svc.SetPolicy(session.Policy{TouchInterval: time.Minute, Toucher: toucher})
	ctx := context.Background()
	tok, sess, err := svc.Issue(ctx, user, "ua", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	aged := sess
	aged.LastSeenAt, aged.CreatedAt = time.Now().Add(-10*time.Minute), time.Now().Add(-10*time.Minute)
	if _, err := store.CreateSession(ctx, aged); err != nil {
		t.Fatal(err)
	}

	const workers = 200
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, _, err := svc.Validate(ctx, tok); err != nil {
				t.Errorf("Validate: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := toucher.n.Load(); got != 1 {
		t.Fatalf("last-seen writes = %d across %d concurrent requests, want 1", got, workers)
	}
	stored, _ := store.SessionByID(ctx, sess.ID)
	if time.Since(stored.LastSeenAt) > 5*time.Second {
		t.Fatalf("LastSeenAt not advanced: %v", stored.LastSeenAt)
	}
	if _, _, err := svc.Validate(ctx, tok); err != nil || toucher.n.Load() != 1 {
		t.Fatalf("validate inside interval touched again: n=%d err=%v", toucher.n.Load(), err)
	}
}

func TestCheckDoesNotTouch(t *testing.T) {
	svc, store, user := setup(t)
	toucher := &countingToucher{store: store}
	svc.SetPolicy(session.Policy{TouchInterval: time.Nanosecond, Toucher: toucher})
	ctx := context.Background()
	tok, _, _ := svc.Issue(ctx, user, "", "")
	time.Sleep(time.Millisecond)
	if _, _, err := svc.Check(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if toucher.n.Load() != 0 {
		t.Fatal("Check must not write last-seen")
	}
}

func TestIdleTimeout(t *testing.T) {
	svc, store, user := setup(t)
	svc.SetPolicy(session.Policy{IdleTimeout: time.Hour})
	ctx := context.Background()
	tests := []struct {
		name     string
		lastSeen time.Duration
		created  time.Duration
		zeroLast bool
		wantErr  error
	}{
		{"recent", time.Minute, time.Minute, false, nil},
		{"idle past timeout", 2 * time.Hour, 3 * time.Hour, false, models.ErrSessionExpired},
		{"no last seen falls back to created, fresh", 0, time.Minute, true, nil},
		{"no last seen falls back to created, stale", 0, 2 * time.Hour, true, models.ErrSessionExpired},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tag := string(rune('a' + i))
			h := hashOf(t, tag)
			s := models.Session{
				ID: ulid.New(), UserID: user.ID, TokenHash: h,
				CreatedAt: time.Now().Add(-tc.created), ExpiresAt: time.Now().Add(time.Hour),
			}
			if !tc.zeroLast {
				s.LastSeenAt = time.Now().Add(-tc.lastSeen)
			}
			if _, err := store.CreateSession(ctx, s); err != nil {
				t.Fatal(err)
			}
			_, _, err := svc.Validate(ctx, tag)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestCredentialRecheckEveryUse(t *testing.T) {
	tests := []struct {
		name      string
		checker   func(calls *atomic.Int64) session.CredentialChecker
		wantErr   func(error) bool
		wantRevok int64
	}{
		{"no checker fails closed", nil, func(err error) bool { return errors.Is(err, models.ErrSessionExpired) }, 0},
		{"valid", func(c *atomic.Int64) session.CredentialChecker {
			return checkerFunc(func(context.Context, string) error { c.Add(1); return nil })
		}, func(err error) bool { return err == nil }, 0},
		{"revoked revokes the session", func(c *atomic.Int64) session.CredentialChecker {
			return checkerFunc(func(context.Context, string) error { c.Add(1); return models.ErrCredentialRevoked })
		}, func(err error) bool { return errors.Is(err, models.ErrSessionExpired) }, 1},
		{"transient error is not expiry", func(c *atomic.Int64) session.CredentialChecker {
			return checkerFunc(func(context.Context, string) error { c.Add(1); return errors.New("db down") })
		}, func(err error) bool { return err != nil && !errors.Is(err, models.ErrSessionExpired) }, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, store, user := setup(t)
			var calls atomic.Int64
			rec := &revokeRecorder{store: store}
			p := session.Policy{Revoker: rec}
			if tc.checker != nil {
				p.Credentials = tc.checker(&calls)
			}
			svc.SetPolicy(p)
			ctx := context.Background()
			tok, sess, err := svc.IssueWith(ctx, user, session.IssueOptions{CredentialID: "cred-1", TTL: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			if sess.CredentialID != "cred-1" || time.Until(sess.ExpiresAt) > time.Minute {
				t.Fatalf("issue options ignored: %+v", sess)
			}
			for i := 0; i < 3; i++ {
				_, _, err := svc.Validate(ctx, tok)
				if tc.name == "revoked revokes the session" && i > 0 {
					if !errors.Is(err, models.ErrSessionExpired) {
						t.Fatalf("use %d after revoke: %v", i, err)
					}
					continue
				}
				if !tc.wantErr(err) {
					t.Fatalf("use %d: unexpected err %v", i, err)
				}
			}
			if rec.revoked.Load() < tc.wantRevok {
				t.Fatalf("revokes = %d, want >= %d", rec.revoked.Load(), tc.wantRevok)
			}
			if tc.name == "valid" && calls.Load() != 3 {
				t.Fatalf("checker calls = %d, want 3 (every use)", calls.Load())
			}
		})
	}
}

type checkerFunc func(ctx context.Context, id string) error

func (f checkerFunc) CheckCredential(ctx context.Context, id string) error { return f(ctx, id) }

func hashOf(t *testing.T, tok string) []byte {
	t.Helper()
	return crypto.HashToken(tok)
}
