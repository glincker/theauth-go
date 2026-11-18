package attest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const statusBody = `{"entries":{"ABC123":{"status":"REVOKED"},"1f":{"status":"SUSPENDED"},"2d":{"status":"OK"}}}`

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func statusServer(t *testing.T, calls *atomic.Int32, handler func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		handler(w)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGoogleRevocationListFlagsAndCaches(t *testing.T) {
	var calls atomic.Int32
	srv := statusServer(t, &calls, func(w http.ResponseWriter) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte(statusBody))
	})
	clk := &fakeClock{t: time.Unix(1000, 0)}
	check := GoogleRevocationList(GoogleRevocationListOptions{URL: srv.URL, Now: clk.now})
	ctx := context.Background()
	for serial, want := range map[string]bool{"abc123": true, "ABC123": true, "1f": true, "2d": false, "ff": false} {
		got, err := check(ctx, serial)
		if err != nil || got != want {
			t.Fatalf("%s: got %v %v, want %v", serial, got, err, want)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
	clk.t = clk.t.Add(61 * time.Second)
	if _, err := check(ctx, "ff"); err != nil || calls.Load() != 2 {
		t.Fatalf("refresh after max-age: err=%v calls=%d", err, calls.Load())
	}
}

func TestGoogleRevocationListFailsClosed(t *testing.T) {
	var calls atomic.Int32
	cases := map[string]func(w http.ResponseWriter){
		"status": func(w http.ResponseWriter) { http.Error(w, "no", http.StatusServiceUnavailable) },
		"empty":  func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{}`)) },
		"junk":   func(w http.ResponseWriter) { _, _ = w.Write([]byte(`nope`)) },
	}
	for name, h := range cases {
		srv := statusServer(t, &calls, h)
		check := GoogleRevocationList(GoogleRevocationListOptions{URL: srv.URL})
		if revoked, err := check(context.Background(), "1"); err == nil || revoked {
			t.Fatalf("%s: want an error, got revoked=%v err=%v", name, revoked, err)
		}
	}
}

func TestGoogleRevocationListStaleGrace(t *testing.T) {
	var calls atomic.Int32
	var failing atomic.Bool
	srv := statusServer(t, &calls, func(w http.ResponseWriter) {
		if failing.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = w.Write([]byte(statusBody))
	})
	clk := &fakeClock{t: time.Unix(0, 0)}
	check := GoogleRevocationList(GoogleRevocationListOptions{URL: srv.URL, Now: clk.now, StaleIfError: 100 * time.Second})
	ctx := context.Background()
	if _, err := check(ctx, "1"); err != nil {
		t.Fatal(err)
	}
	failing.Store(true)
	clk.t = time.Unix(80, 0)
	if revoked, err := check(ctx, "abc123"); err != nil || !revoked {
		t.Fatalf("inside the grace period the stale list answers: %v %v", revoked, err)
	}
	clk.t = time.Unix(200, 0)
	if _, err := check(ctx, "1"); err == nil {
		t.Fatal("past the grace period the check must fail")
	}
}

func TestAndroidVerifierSurfacesRevocationErrors(t *testing.T) {
	f := loadFixtures(t)
	chain := f.android.Chains["algorithm_EC_SecurityLevel_TEE"]
	verify, err := NewAndroidKeyVerifier(AndroidKeyOptions{
		BootPolicy: "any", BindKey: Bool(false), Now: func() time.Time { return time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC) },
		Revocation: func(context.Context, string) (bool, error) { return false, context.DeadlineExceeded },
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence := `["` + chain[0] + `","` + chain[1] + `","` + chain[2] + `","` + chain[3] + `"]`
	res, err := verify(context.Background(), Input{Evidence: evidence, Nonce: "abc"})
	if err == nil || res.OK {
		t.Fatalf("a failing revocation lookup must refuse, got %+v %v", res, err)
	}
}
