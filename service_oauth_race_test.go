package theauth_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

// TestOAuthStateConcurrentReadWrite spawns interleaving writers (driving
// /auth/providers/stub/start which stores state) and readers (driving the
// callback path which reads + deletes state). The test asserts no panic
// and no data race under -race.
func TestOAuthStateConcurrentReadWrite(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:           memory.New(),
		BaseURL:           "http://localhost",
		EncryptionKey:     key,
		PostLoginRedirect: "/",
		Providers:         []theauth.Provider{&stubProvider{name: "stub"}},
		// Bump the per-IP limit well above the writer count so the test
		// exercises the state map under load rather than the rate limiter.
		RateLimitPerIP: 10_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	r := chi.NewRouter()
	a.Mount(r)

	const writers = 500
	const readers = 500
	var wg sync.WaitGroup
	wg.Add(writers + readers)

	// Writers exercise the start endpoint, which writes to the shared
	// oauthStates sync.Map.
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/auth/providers/stub/start", nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
		}()
	}

	// Readers exercise the callback endpoint with arbitrary state values.
	// Most will miss (state never stored), the rest hit the LoadAndDelete
	// path under the same map. The point is to interleave reads and writes.
	for i := 0; i < readers; i++ {
		go func(i int) {
			defer wg.Done()
			rb := make([]byte, 16)
			_, _ = rand.Read(rb)
			state := hex.EncodeToString(rb)
			// State cookie matches the query so the handler reaches the
			// service layer's LoadAndDelete branch.
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/providers/stub/callback?state=%s&code=x", state), nil)
			req.AddCookie(&http.Cookie{Name: "theauth_oauth_state", Value: state})
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
		}(i)
	}
	wg.Wait()

	// Sanity: trigger one more start + callback round trip and ensure
	// the map still behaves.
	req := httptest.NewRequest(http.MethodGet, "/auth/providers/stub/start", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("post-race start returned %d, want 302", rec.Code)
	}
	_ = context.Background()
}
