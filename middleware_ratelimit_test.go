package theauth_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
)

func TestRateLimitByIPAllowsBurstThenRejects(t *testing.T) {
	a, _ := newTestAuth(t)
	mw := a.RateLimitByIP(5)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mw(ok))
	t.Cleanup(srv.Close)

	// First 5 should pass (burst budget). 6th should be rejected.
	for i := 0; i < 5; i++ {
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: expected 200; got %d", i+1, resp.StatusCode)
		}
	}
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 6th request; got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got == "" {
		t.Fatal("expected Retry-After header on 429")
	}
}

func TestRateLimitByIPIsolatesDifferentIPs(t *testing.T) {
	a, _ := newTestAuth(t)
	mw := a.RateLimitByIP(2)
	called := 0
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})
	handler := mw(ok)

	rec := func(ip string) int {
		req := httptest.NewRequest("POST", "/", nil)
		req.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	// IP A burns budget. Evaluate sequentially so each request fires (||
	// short-circuiting would skip later calls and corrupt the per-IP
	// counter assertions).
	s1 := rec("1.1.1.1")
	s2 := rec("1.1.1.1")
	s3 := rec("1.1.1.1")
	if s1 != 200 || s2 != 200 || s3 != 429 {
		t.Fatalf("1.1.1.1 sequence wrong: got %d, %d, %d; want 200, 200, 429", s1, s2, s3)
	}
	// IP B is untouched, first request must still pass.
	if rec("2.2.2.2") != 200 {
		t.Fatal("2.2.2.2 should be allowed; isolation broken")
	}
}

// TestRateLimitByIPHonorsXForwardedFor exercises the trusted-proxy
// allowlist contract introduced in security audit H4 (2026-06-20).
// Operators that explicitly trust 127.0.0.1 (the proxy address used by the
// test harness) get the same XFF-keyed behavior as before; the safe
// default (no trust) is covered separately by
// TestRateLimitByIPIgnoresXForwardedForByDefault.
func TestRateLimitByIPHonorsXForwardedFor(t *testing.T) {
	a, err := theauth.New(theauth.Config{
		Storage:        memory.New(),
		BaseURL:        "http://localhost",
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	mw := a.RateLimitByIP(1)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw(ok)

	doReq := func(xff string) int {
		req := httptest.NewRequest("POST", "/", nil)
		req.RemoteAddr = "127.0.0.1:9999" // proxy address (trusted)
		req.Header.Set("X-Forwarded-For", xff)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	// First request from real client A: passes.
	if doReq("9.9.9.9") != 200 {
		t.Fatal("first client A req should pass")
	}
	// Second request from client A: 429.
	if doReq("9.9.9.9") != 429 {
		t.Fatal("second client A req should be 429")
	}
	// First request from client B: passes (limiter keyed on XFF, not on
	// proxy addr).
	if doReq("8.8.8.8") != 200 {
		t.Fatal("client B should be isolated from A")
	}
}

// TestRateLimitByIPIgnoresXForwardedForByDefault locks in the security
// audit H4 (2026-06-20) regression: when no TrustedProxies are configured,
// the X-Forwarded-For header is NOT honored. An attacker rotating XFF on
// every request from a single source IP must NOT bypass the per-IP cap.
func TestRateLimitByIPIgnoresXForwardedForByDefault(t *testing.T) {
	a, _ := newTestAuth(t) // newTestAuth does not set TrustedProxies.
	mw := a.RateLimitByIP(1)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw(ok)

	doReq := func(xff string) int {
		req := httptest.NewRequest("POST", "/", nil)
		req.RemoteAddr = "203.0.113.7:9999" // same upstream every time
		req.Header.Set("X-Forwarded-For", xff)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	// First request: passes.
	if doReq("9.9.9.9") != 200 {
		t.Fatal("first request should pass")
	}
	// Second request with a forged XFF from a different "client":
	// without TrustedProxies the limiter still keys off RemoteAddr, so
	// this must 429. If the test sees 200, the H4 fix has regressed.
	if got := doReq("8.8.8.8"); got != 429 {
		t.Fatalf("forged XFF must not refresh the per-IP budget; got %d (want 429)", got)
	}
	// Third request with the original XFF: also 429 (still keyed on the
	// upstream RemoteAddr).
	if got := doReq("9.9.9.9"); got != 429 {
		t.Fatalf("second request from the same RemoteAddr must be 429; got %d", got)
	}
}

// TestRateLimitByIPHonorsXForwardedForOnlyForTrustedProxies confirms that
// when TrustedProxies is set but the request RemoteAddr is NOT inside the
// allowlist, XFF is ignored (security audit H4 regression coverage).
func TestRateLimitByIPHonorsXForwardedForOnlyForTrustedProxies(t *testing.T) {
	a, err := theauth.New(theauth.Config{
		Storage:        memory.New(),
		BaseURL:        "http://localhost",
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	mw := a.RateLimitByIP(1)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw(ok)

	doReq := func(remote, xff string) int {
		req := httptest.NewRequest("POST", "/", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", xff)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	// Untrusted upstream: XFF ignored, second request 429 even with new
	// XFF value.
	if doReq("203.0.113.7:1111", "9.9.9.9") != 200 {
		t.Fatal("first untrusted req should pass")
	}
	if got := doReq("203.0.113.7:1111", "1.1.1.1"); got != 429 {
		t.Fatalf("untrusted upstream must not honor XFF; got %d", got)
	}
	// Trusted upstream (10.x.x.x): XFF honored, distinct XFF gets a
	// fresh bucket.
	if doReq("10.0.0.1:1111", "9.9.9.9") != 200 {
		t.Fatal("first trusted req should pass")
	}
	if doReq("10.0.0.1:1111", "9.9.9.9") != 429 {
		t.Fatal("second trusted req from same XFF should be 429")
	}
	if doReq("10.0.0.1:1111", "8.8.8.8") != 200 {
		t.Fatal("trusted upstream with different XFF should get a fresh bucket")
	}
}

func TestRateLimitByEmailExtractsAndRestoresBody(t *testing.T) {
	a, _ := newTestAuth(t)
	mw := a.RateLimitByEmail(2)

	// Downstream handler reads the body, verifies the middleware restored it.
	var seen []string
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		var body struct{ Email string }
		_ = json.Unmarshal(buf, &body)
		seen = append(seen, body.Email)
		w.WriteHeader(http.StatusOK)
	})
	handler := mw(downstream)

	send := func(email string) int {
		b, _ := json.Marshal(map[string]string{"email": email})
		req := httptest.NewRequest("POST", "/", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	// Evaluate sequentially: || short-circuit would skip the second call.
	first := send("a@h.com")
	second := send("a@h.com")
	if first != 200 || second != 200 {
		t.Fatalf("first 2 to a@h.com should pass; got %d, %d", first, second)
	}
	if send("a@h.com") != 429 {
		t.Fatal("3rd to a@h.com should 429")
	}
	if send("b@h.com") != 200 {
		t.Fatal("first to b@h.com should pass, isolation broken")
	}
	for _, e := range seen {
		if e != "a@h.com" && e != "b@h.com" {
			t.Fatalf("downstream got unexpected email %q (body restoration failed)", e)
		}
	}
}

// Verifies the GC goroutine evicts limiters with no recent traffic.
func TestKeyedLimiterGC(t *testing.T) {
	k := theauth.NewKeyedLimiterForTest(5, 30*time.Millisecond, 10*time.Millisecond)
	t.Cleanup(k.Stop)
	_ = k.Allow("a")
	_ = k.Allow("b")
	if k.EntryCount() != 2 {
		t.Fatalf("expected 2 entries; got %d", k.EntryCount())
	}
	// Wait long enough for at least one GC tick after the evictAfter window.
	time.Sleep(120 * time.Millisecond)
	if got := k.EntryCount(); got != 0 {
		t.Fatalf("expected GC to evict idle keys; got %d", got)
	}
}
