package theauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
)

// newFuzzAuth constructs a TheAuth instance with the in-memory adapter
// and returns it along with the cookie name used for session lookup.
func newFuzzAuth(t testing.TB) *theauth.TheAuth {
	t.Helper()
	a, err := theauth.New(theauth.Config{
		Storage:      memory.New(),
		BaseURL:      "http://localhost",
		SecureCookie: false,
	})
	if err != nil {
		t.Fatalf("new theauth: %v", err)
	}
	t.Cleanup(a.Close)
	return a
}

// FuzzParseSessionCookie drives arbitrary Cookie header bytes through
// the Authn middleware. The handler underneath only fires for valid
// (non-anonymous) sessions, so the assertion is "no panic regardless of
// header shape" and "anonymous outcome for malformed cookies".
func FuzzParseSessionCookie(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("theauth_session=abc"))
	f.Add([]byte("theauth_session=\x00\x01\x02"))

	a := newFuzzAuth(f)
	h := a.Authn()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := theauth.UserFromContext(r.Context()); ok {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			raw = raw[:8192]
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Cookie", string(raw))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		// We don't pre-create any session, so an authenticated outcome
		// would indicate a serious bug (random cookie matched).
		if rec.Code == http.StatusOK {
			t.Fatalf("unexpected authenticated outcome for arbitrary cookie")
		}
	})
}

// FuzzParseStateCookie drives arbitrary Cookie header bytes through the
// OAuth callback handler (which reads the theauth_oauth_state cookie).
// The handler must never panic and must respond with a 4xx for any
// malformed input. We register a fake provider so the {name} route exists.
func FuzzParseStateCookie(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("theauth_oauth_state=somestate"))
	f.Add([]byte("theauth_oauth_state=\x00\x01"))

	// Build a TheAuth with a stub provider so /providers/{name}/callback
	// is mounted. Mount through chi to mirror production wiring.
	a, mux := newOAuthFuzzAuth(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			raw = raw[:8192]
		}
		// Hit the callback with stubbed state plus code query to exercise
		// the state cookie parse branch. The handler should return 400 on
		// any malformed cookie and must not panic.
		req := httptest.NewRequest(http.MethodGet, "/auth/providers/stub/callback?state=x&code=y", nil)
		req.Header.Set("Cookie", string(raw))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("server-side error for arbitrary state cookie: %d", rec.Code)
		}
		_ = a
	})
}
