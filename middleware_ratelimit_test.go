package theauth_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
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
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: expected 200; got %d", i+1, resp.StatusCode)
		}
	}
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
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
	// IP A burns budget.
	if rec("1.1.1.1") != 200 || rec("1.1.1.1") != 200 || rec("1.1.1.1") != 429 {
		t.Fatal("1.1.1.1 sequence wrong")
	}
	// IP B is untouched — first request must still pass.
	if rec("2.2.2.2") != 200 {
		t.Fatal("2.2.2.2 should be allowed; isolation broken")
	}
}

func TestRateLimitByIPHonorsXForwardedFor(t *testing.T) {
	a, _ := newTestAuth(t)
	mw := a.RateLimitByIP(1)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw(ok)

	doReq := func(xff string) int {
		req := httptest.NewRequest("POST", "/", nil)
		req.RemoteAddr = "127.0.0.1:9999" // proxy address
		req.Header.Set("X-Forwarded-For", xff)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	// First request from real client A — passes.
	if doReq("9.9.9.9") != 200 {
		t.Fatal("first client A req should pass")
	}
	// Second request from client A — 429.
	if doReq("9.9.9.9") != 429 {
		t.Fatal("second client A req should be 429")
	}
	// First request from client B — passes (limiter keyed on XFF, not on proxy addr).
	if doReq("8.8.8.8") != 200 {
		t.Fatal("client B should be isolated from A")
	}
}

func TestRateLimitByEmailExtractsAndRestoresBody(t *testing.T) {
	a, _ := newTestAuth(t)
	mw := a.RateLimitByEmail(2)

	// Downstream handler reads the body — verifies the middleware restored it.
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
	if send("a@h.com") != 200 || send("a@h.com") != 200 {
		t.Fatal("first 2 to a@h.com should pass")
	}
	if send("a@h.com") != 429 {
		t.Fatal("3rd to a@h.com should 429")
	}
	if send("b@h.com") != 200 {
		t.Fatal("first to b@h.com should pass — isolation broken")
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
