package integration

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

// recordingThrottleStore wraps a LoginThrottleStore and remembers every key written.
type recordingThrottleStore struct {
	theauth.LoginThrottleStore
	mu   sync.Mutex
	keys []string
}

func (s *recordingThrottleStore) Set(ctx context.Context, key string, e theauth.LoginThrottleEntry) error {
	s.mu.Lock()
	s.keys = append(s.keys, key)
	s.mu.Unlock()
	return s.LoginThrottleStore.Set(ctx, key, e)
}

func (s *recordingThrottleStore) hasKey(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k == key {
			return true
		}
	}
	return false
}

// TestPasswordHandlersResolveClientIPBehindTrustedProxy proves that the password sign-in
// throttle key and the session IP use the proxy-aware client address, and ignore
// X-Forwarded-For unless the peer is a trusted proxy.
func TestPasswordHandlersResolveClientIPBehindTrustedProxy(t *testing.T) {
	proxyNet := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}
	tests := []struct {
		name    string
		trusted []netip.Prefix
		remote  string
		xff     []string
		want    string
	}{
		{"trusted proxy uses forwarded client", proxyNet, "10.0.0.5:4444", []string{"198.51.100.9"}, "198.51.100.9"},
		{"no trusted proxies ignores header", nil, "203.0.113.7:4444", []string{"198.51.100.9"}, "203.0.113.7"},
		{"untrusted peer ignores header", proxyNet, "203.0.113.7:4444", []string{"198.51.100.9"}, "203.0.113.7"},
		{"spoofed multi hop takes rightmost untrusted", proxyNet, "10.0.0.5:4444", []string{"1.2.3.4, 198.51.100.9, 10.0.0.7"}, "198.51.100.9"},
		{"multiple header lines are one list", proxyNet, "10.0.0.5:4444", []string{"1.2.3.4", "198.51.100.9"}, "198.51.100.9"},
		{"ipv6 forwarded client", proxyNet, "10.0.0.5:4444", []string{"2001:db8::1"}, "2001:db8::1"},
		{"ipv6 trusted proxy peer", proxyNet, "[fd00::1]:4444", []string{"198.51.100.9"}, "198.51.100.9"},
		{"ipv6 untrusted peer keeps remote", proxyNet, "[2001:db8::7]:4444", []string{"198.51.100.9"}, "2001:db8::7"},
		{"invalid forwarded entry falls back to peer", proxyNet, "10.0.0.5:4444", []string{"not-an-ip"}, "10.0.0.5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := memory.New()
			rec := &recordingThrottleStore{LoginThrottleStore: theauth.NewMemoryLoginThrottleStore(0)}
			a, err := theauth.New(theauth.Config{
				Storage:           store,
				BaseURL:           "http://localhost",
				SessionTTL:        time.Hour,
				RateLimitPerIP:    100,
				RateLimitPerEmail: 100,
				TrustedProxies:    tc.trusted,
				LoginThrottle:     &theauth.LoginThrottleConfig{Store: rec},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(a.Close)
			r := chi.NewRouter()
			a.Mount(r)

			do := func(path, body string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
				req.Header.Set("Content-Type", "application/json")
				req.RemoteAddr = tc.remote
				for _, v := range tc.xff {
					req.Header.Add("X-Forwarded-For", v)
				}
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				return w
			}

			const email = "proxy@example.com"
			if w := do("/auth/email-password/signup", `{"email":"`+email+`","password":"correct-horse-battery-1"}`); w.Code != http.StatusCreated {
				t.Fatalf("signup: %d %s", w.Code, w.Body.String())
			}
			if w := do("/auth/email-password/signin", `{"email":"`+email+`","password":"correct-horse-battery-1"}`); w.Code != http.StatusOK {
				t.Fatalf("signin: %d %s", w.Code, w.Body.String())
			}
			if w := do("/auth/email-password/signin", `{"email":"`+email+`","password":"wrong-password-xyz"}`); w.Code == http.StatusOK {
				t.Fatalf("bad signin unexpectedly succeeded")
			}

			if want := "login:" + tc.want + "|" + email; !rec.hasKey(want) {
				t.Errorf("throttle key %q not recorded; keys=%v", want, rec.keys)
			}

			user, err := store.UserByEmail(context.Background(), email)
			if err != nil {
				t.Fatal(err)
			}
			sessions, err := store.ListUserSessions(context.Background(), user.ID)
			if err != nil || len(sessions) == 0 {
				t.Fatalf("sessions: %v %v", sessions, err)
			}
			// Signup and signin sessions must both carry the client IP.
			matched := false
			for _, s := range sessions {
				if s.IP == tc.want {
					matched = true
				} else if s.IP != "" {
					t.Errorf("session IP = %q, want %q", s.IP, tc.want)
				}
			}
			if !matched {
				t.Errorf("no session recorded IP %q", tc.want)
			}
		})
	}
}

// TestPasswordSignupRecordsClientIPAndUserAgent proves that sign up records the same client
// address and user agent on the session row and the audit event as sign in does.
func TestPasswordSignupRecordsClientIPAndUserAgent(t *testing.T) {
	proxyNet := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	tests := []struct {
		name    string
		trusted []netip.Prefix
		remote  string
		xff     string
		want    string
	}{
		{"behind trusted proxy", proxyNet, "10.0.0.5:4444", "198.51.100.9", "198.51.100.9"},
		{"without trusted proxy", nil, "203.0.113.7:4444", "198.51.100.9", "203.0.113.7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := memory.New()
			sink := &auditCapture{}
			a, err := theauth.New(theauth.Config{
				Storage:        store,
				BaseURL:        "http://localhost",
				SessionTTL:     time.Hour,
				TrustedProxies: tc.trusted,
				Audit:          &theauth.AuditConfig{FlushInterval: 10 * time.Millisecond, Sinks: []theauth.AuditSink{sink}},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(a.Close)
			r := chi.NewRouter()
			a.Mount(r)

			const email = "signupip@example.com"
			const agent = "signup-agent/1.0"
			req := httptest.NewRequest(http.MethodPost, "/auth/email-password/signup",
				bytes.NewBufferString(`{"email":"`+email+`","password":"correct-horse-battery-1"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", agent)
			req.Header.Set("X-Forwarded-For", tc.xff)
			req.RemoteAddr = tc.remote
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				t.Fatalf("signup: %d %s", w.Code, w.Body.String())
			}

			user, err := store.UserByEmail(context.Background(), email)
			if err != nil {
				t.Fatal(err)
			}
			sessions, err := store.ListUserSessions(context.Background(), user.ID)
			if err != nil || len(sessions) != 1 {
				t.Fatalf("sessions: %v %v", sessions, err)
			}
			if sessions[0].IP != tc.want {
				t.Errorf("session IP = %q, want %q", sessions[0].IP, tc.want)
			}
			if sessions[0].UserAgent != agent {
				t.Errorf("session user agent = %q, want %q", sessions[0].UserAgent, agent)
			}

			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				sink.mu.Lock()
				for _, ev := range sink.events {
					if ev.Action != "user.login" {
						continue
					}
					defer sink.mu.Unlock()
					if ev.IP != tc.want || ev.UserAgent != agent {
						t.Errorf("audit ip/ua = %q/%q, want %q/%q", ev.IP, ev.UserAgent, tc.want, agent)
					}
					if ev.ActorUserID == nil || *ev.ActorUserID != user.ID {
						t.Errorf("audit actor = %v, want %v", ev.ActorUserID, user.ID)
					}
					return
				}
				sink.mu.Unlock()
				time.Sleep(20 * time.Millisecond)
			}
			t.Fatal("no user.login audit event for signup")
		})
	}
}
