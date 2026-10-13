package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/kv"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

type admitFailLimiter struct{ calls int }

func (f *admitFailLimiter) Allow(context.Context, string, int, time.Duration) (kv.Decision, error) {
	f.calls++
	return kv.Decision{}, errors.New("store down")
}

type admitRecLimiter struct{ keys []string }

func (r *admitRecLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (kv.Decision, error) {
	r.keys = append(r.keys, key)
	return kv.Decision{Allowed: true}, nil
}

func admissionAuth(t *testing.T, stores kv.Stores, trusted []string) *theauth.TheAuth {
	t.Helper()
	a, err := theauth.New(theauth.Config{
		Storage:        memory.New(),
		BaseURL:        "https://app.example.com",
		TrustedOrigins: trusted,
		Stores:         stores,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

var admitOK = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

func admitDo(h http.Handler, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://app.example.com"+path, nil)
	r.RemoteAddr = "203.0.113.9:1234"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAdmissionTierSelection(t *testing.T) {
	a := admissionAuth(t, kv.Stores{}, nil)
	h := a.Admission(theauth.AdmissionOptions{
		DisableCSRF: true,
		Limits: theauth.AdmissionLimits{
			Strict:   theauth.AdmissionLimit{Max: 1},
			Mutation: theauth.AdmissionLimit{Max: 2},
			Read:     theauth.AdmissionLimit{Max: 3},
		},
	})(admitOK)
	cases := []struct {
		method, path string
		max          int
	}{
		{"POST", "/oauth/token", 1},
		{"GET", "/auth/me", 3},
		{"POST", "/auth/signout", 2},
	}
	// Distinct client per case via Key would hide tiers sharing a key, so use
	// one client and distinct tiers: each tier keeps its own counter.
	for _, c := range cases {
		for i := 1; i <= c.max; i++ {
			if w := admitDo(h, c.method, c.path, nil); w.Code != 200 {
				t.Fatalf("%s %s req %d: %d", c.method, c.path, i, w.Code)
			}
		}
		if w := admitDo(h, c.method, c.path, nil); w.Code != 429 {
			t.Fatalf("%s %s over limit: got %d want 429", c.method, c.path, w.Code)
		}
	}
}

func TestAdmissionStrictSuffixMatching(t *testing.T) {
	a := admissionAuth(t, kv.Stores{}, nil)
	h := a.Admission(theauth.AdmissionOptions{
		DisableCSRF: true,
		Limits:      theauth.AdmissionLimits{Strict: theauth.AdmissionLimit{Max: 1}},
	})(admitOK)
	// Mount prefix in front of a strict path still counts as strict.
	if admitDo(h, "GET", "/v1/auth/mcp/token", nil).Code != 200 {
		t.Fatal("first request refused")
	}
	if admitDo(h, "GET", "/v1/auth/mcp/token", nil).Code != 429 {
		t.Fatal("suffix match did not use strict tier")
	}
	// Not a suffix match: read tier, far from the strict cap of 1.
	for i := 0; i < 5; i++ {
		if w := admitDo(h, "GET", "/auth/tokens", nil); w.Code != 200 {
			t.Fatalf("/auth/tokens wrongly strict: %d", w.Code)
		}
	}
	// Case-insensitive.
	if admitDo(h, "POST", "/OAuth/Token", nil).Code != 429 {
		t.Fatal("case-insensitive strict match missing (shares strict bucket)")
	}
}

func TestAdmission429Shape(t *testing.T) {
	a := admissionAuth(t, kv.Stores{}, nil)
	h := a.Admission(theauth.AdmissionOptions{
		DisableCSRF: true,
		Limits:      theauth.AdmissionLimits{Read: theauth.AdmissionLimit{Max: 1, Window: 30 * time.Second}},
	})(admitOK)
	admitDo(h, "GET", "/x", nil)
	w := admitDo(h, "GET", "/x", nil)
	if w.Code != 429 {
		t.Fatalf("got %d", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra != "30" {
		t.Fatalf("Retry-After = %q want 30", ra)
	}
	var body struct{ Code, Message string }
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Code != "RATE_LIMITED" {
		t.Fatalf("body %s err %v", w.Body.String(), err)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content type %q", ct)
	}
}

func TestAdmissionCrossSite(t *testing.T) {
	a := admissionAuth(t, kv.Stores{}, []string{"https://partner.example.com"})
	h := a.Admission(theauth.AdmissionOptions{
		DisableRateLimit: true,
		TrustedOrigins:   []string{"https://extra.example.com"},
	})(admitOK)
	cookie := map[string]string{"Cookie": "sid=abc"}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{"Cookie": "sid=abc"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name   string
		method string
		hdr    map[string]string
		want   int
	}{
		{"cross-site origin refused", "POST", with(map[string]string{"Origin": "https://evil.example"}), 403},
		{"same origin allowed", "POST", with(map[string]string{"Origin": "https://app.example.com"}), 200},
		{"config trusted origin allowed", "POST", with(map[string]string{"Origin": "https://partner.example.com"}), 200},
		{"admission trusted origin allowed", "POST", with(map[string]string{"Origin": "https://extra.example.com"}), 200},
		{"sec-fetch-site cross-site no origin refused", "POST", with(map[string]string{"Sec-Fetch-Site": "cross-site"}), 403},
		{"sec-fetch-site same-origin allowed", "POST", with(map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://evil.example"}), 200},
		{"bearer exempt", "POST", map[string]string{"Authorization": "Bearer t", "Cookie": "sid=abc", "Origin": "https://evil.example"}, 200},
		{"no cookie exempt", "POST", map[string]string{"Origin": "https://evil.example"}, 200},
		{"safe method exempt", "GET", with(map[string]string{"Origin": "https://evil.example"}), 200},
	}
	_ = cookie
	for _, c := range cases {
		w := admitDo(h, c.method, "/auth/signout", c.hdr)
		if w.Code != c.want {
			t.Errorf("%s: got %d want %d", c.name, w.Code, c.want)
		}
		if c.want == 403 && !strings.Contains(w.Body.String(), "CSRF_REJECTED") {
			t.Errorf("%s: body %s", c.name, w.Body.String())
		}
	}
	off := a.Admission(theauth.AdmissionOptions{DisableRateLimit: true, DisableCSRF: true})(admitOK)
	if w := admitDo(off, "POST", "/x", map[string]string{"Cookie": "a=b", "Origin": "https://evil.example"}); w.Code != 200 {
		t.Fatalf("csrf disabled: %d", w.Code)
	}
}

func TestAdmissionKeyFallback(t *testing.T) {
	rec := &admitRecLimiter{}
	a := admissionAuth(t, kv.Stores{RateLimiter: rec}, nil)
	h := a.Admission(theauth.AdmissionOptions{DisableCSRF: true})(admitOK)
	run := func(remote string, hdr map[string]string) string {
		r := httptest.NewRequest("GET", "https://app.example.com/x", nil)
		r.RemoteAddr = remote
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
		return rec.keys[len(rec.keys)-1]
	}
	if k := run("203.0.113.9:1", nil); k != "admit:read:ip:203.0.113.9" {
		t.Fatalf("ip key %q", k)
	}
	k := run("", map[string]string{"Authorization": "Bearer secret-token"})
	if !strings.HasPrefix(k, "admit:read:cred:") || strings.Contains(k, "secret") {
		t.Fatalf("cred key %q", k)
	}
	if k := run("", nil); k != "admit:read:unknown" {
		t.Fatalf("unknown key %q", k)
	}
	// Custom key wins; empty return falls back.
	h2 := a.Admission(theauth.AdmissionOptions{
		DisableCSRF: true,
		Key: func(r *http.Request) string {
			return r.Header.Get("X-Tenant")
		},
	})(admitOK)
	r := httptest.NewRequest("GET", "https://app.example.com/x", nil)
	r.Header.Set("X-Tenant", "t1")
	h2.ServeHTTP(httptest.NewRecorder(), r)
	if got := rec.keys[len(rec.keys)-1]; got != "admit:read:t1" {
		t.Fatalf("custom key %q", got)
	}
}

func TestAdmissionFailsOpenOnStoreError(t *testing.T) {
	f := &admitFailLimiter{}
	a := admissionAuth(t, kv.Stores{RateLimiter: f}, nil)
	h := a.Admission(theauth.AdmissionOptions{DisableCSRF: true})(admitOK)
	if w := admitDo(h, "GET", "/x", nil); w.Code != 200 {
		t.Fatalf("got %d", w.Code)
	}
	if f.calls == 0 {
		t.Fatal("store not consulted")
	}
}

func TestAdmissionSkip(t *testing.T) {
	a := admissionAuth(t, kv.Stores{}, nil)
	h := a.Admission(theauth.AdmissionOptions{
		DisableCSRF: true,
		Limits:      theauth.AdmissionLimits{Read: theauth.AdmissionLimit{Max: 1}},
		Skip:        func(r *http.Request) bool { return r.URL.Path == "/healthz" },
	})(admitOK)
	for i := 0; i < 3; i++ {
		if admitDo(h, "GET", "/healthz", nil).Code != 200 {
			t.Fatal("skipped path limited")
		}
	}
}

func TestAdmissionMountOptIn(t *testing.T) {
	a, err := theauth.New(theauth.Config{
		Storage:   memory.New(),
		BaseURL:   "https://app.example.com",
		Admission: &theauth.AdmissionOptions{Limits: theauth.AdmissionLimits{Read: theauth.AdmissionLimit{Max: 1}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	h := a.Handler()
	admitDo(h, "GET", "/auth/me", nil)
	if w := admitDo(h, "GET", "/auth/me", nil); w.Code != 429 {
		t.Fatalf("mounted admission not applied: %d", w.Code)
	}
}
