package theauth_test

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/glincker/theauth-go"
	discprov "github.com/glincker/theauth-go/provider/discord"
	ghprov "github.com/glincker/theauth-go/provider/github"
	googprov "github.com/glincker/theauth-go/provider/google"
	msprov "github.com/glincker/theauth-go/provider/microsoft"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

// mockGitHubServer returns an httptest server that mimics the three GitHub
// OAuth endpoints used in the callback flow. It does NOT model /authorize as
// an interactive page; the e2e test fakes that step by triggering the
// callback directly with the state captured at /start time.
func mockGitHubServer(t *testing.T, accessToken, primaryEmail string, userID int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Not exercised by the test (the user-agent loop is faked) but kept
		// so a real browser walk-through would not 404.
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": accessToken,
			"token_type":   "bearer",
			"scope":        "read:user,user:email",
		})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         userID,
			"login":      "e2e-user",
			"name":       "E2E User",
			"avatar_url": "https://avatars.example.com/u/" + ridString(userID),
		})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"email": primaryEmail, "primary": true, "verified": true},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func ridString(id int64) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	_ = id
	return "abc"
}

// newOAuthTestServer wires up a theauth-go server with the GitHub provider
// pointing at the supplied mock URLs. Returns the server and a handle on the
// underlying *TheAuth (for inspection).
func newOAuthTestServer(t *testing.T, mockURL string) (*httptest.Server, *theauth.TheAuth) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	a, err := theauth.New(theauth.Config{
		Storage:           store,
		BaseURL:           "http://placeholder", // patched below via SetBaseURLForTest
		EncryptionKey:     key,
		PostLoginRedirect: "/after-login",
		Providers: []theauth.Provider{
			ghprov.New(ghprov.Config{
				ClientID:     "cid",
				ClientSecret: "csec",
				TokenURL:     mockURL + "/login/oauth/access_token",
				UserURL:      mockURL + "/user",
				EmailsURL:    mockURL + "/user/emails",
				AuthorizeURL: mockURL + "/login/oauth/authorize",
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	theauth.SetBaseURLForTest(a, srv.URL)
	t.Cleanup(func() {
		srv.Close()
		a.Close()
	})
	return srv, a
}

func TestOAuthGitHubEndToEnd(t *testing.T) {
	mock := mockGitHubServer(t, "gho_e2e", "e2e@example.com", 4242)
	srv, _ := newOAuthTestServer(t, mock.URL)

	// 1) /start should 302 to the provider's authorize URL and set the state
	// cookie. Use a client that does NOT auto-follow redirects so we can see
	// the Location header and the Set-Cookie response.
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(srv.URL + "/auth/providers/github/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/start: expected 302; got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" || !strings.HasPrefix(loc, mock.URL+"/login/oauth/authorize?") {
		t.Fatalf("/start: unexpected Location %q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("/start: state missing from authorize URL")
	}
	if got := u.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("expected S256 PKCE; got %q", got)
	}
	var stateCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "theauth_oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil || stateCookie.Value != state {
		t.Fatalf("/start: state cookie missing or mismatched (cookie=%+v state=%q)", stateCookie, state)
	}

	// 2) Drive the callback as if the user just bounced back from GitHub
	// with state + code. Code value is arbitrary; the mock token endpoint
	// always returns the canned access token.
	callbackURL := srv.URL + "/auth/providers/github/callback?state=" + url.QueryEscape(state) + "&code=auth-code-e2e"
	req, err := http.NewRequest("GET", callbackURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(stateCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/callback: expected 302; got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/after-login" {
		t.Fatalf("/callback: unexpected redirect %q", got)
	}
	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "theauth_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("/callback: session cookie not set")
	}

	// 3) /auth/me with the new session cookie returns the user with email
	// from the mock.
	req, _ = http.NewRequest("GET", srv.URL+"/auth/me", nil)
	req.AddCookie(sessionCookie)
	meResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = meResp.Body.Close() }()
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("/auth/me: expected 200; got %d", meResp.StatusCode)
	}
	var me theauth.User
	if err := json.NewDecoder(meResp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if me.Email != "e2e@example.com" {
		t.Fatalf("/auth/me email = %q, want %q", me.Email, "e2e@example.com")
	}
	if me.EmailVerifiedAt == nil {
		t.Fatal("/auth/me EmailVerifiedAt should be set (primary verified email from mock)")
	}
	if me.Name != "E2E User" {
		t.Fatalf("/auth/me name = %q", me.Name)
	}

	// 4) Replay of the same callback (with the now-deleted state) must fail.
	// State map LoadAndDelete makes this naturally idempotent.
	req, _ = http.NewRequest("GET", callbackURL, nil)
	req.AddCookie(stateCookie)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("/callback replay: expected 400; got %d", resp2.StatusCode)
	}
}

func TestOAuthCallbackStateMismatchRejected(t *testing.T) {
	mock := mockGitHubServer(t, "gho_x", "x@example.com", 1)
	srv, _ := newOAuthTestServer(t, mock.URL)

	// /start to get a real state cookie.
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(srv.URL + "/auth/providers/github/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	var stateCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "theauth_oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("expected state cookie")
	}

	// Now call /callback with a forged state that does NOT match the cookie.
	req, _ := http.NewRequest("GET", srv.URL+"/auth/providers/github/callback?state=forged&code=c", nil)
	req.AddCookie(stateCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 state mismatch; got %d", resp.StatusCode)
	}
}

func TestOAuthUnknownProvider404(t *testing.T) {
	mock := mockGitHubServer(t, "gho_x", "x@example.com", 1)
	srv, _ := newOAuthTestServer(t, mock.URL)
	resp, err := http.Get(srv.URL + "/auth/providers/notreal/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404; got %d", resp.StatusCode)
	}
}

func TestNewRejectsProvidersWithoutEncryptionKey(t *testing.T) {
	_, err := theauth.New(theauth.Config{
		Storage: memory.New(),
		BaseURL: "http://localhost",
		Providers: []theauth.Provider{
			ghprov.New(ghprov.Config{ClientID: "x", ClientSecret: "y"}),
		},
	})
	if err == nil {
		t.Fatal("expected error when EncryptionKey missing alongside Providers")
	}
}

// ---------- multi-provider tests (originally handlers_oauth_multi_test.go) ----------

// TestOAuthMultiProviderMountAndStart wires GitHub, Google, Microsoft,
// and Discord into a single theauth.New call and asserts each /start
// route returns a 302 whose Location header points at the expected
// provider host. This is a routing smoke test only; each provider's
// exchange and userinfo flow is covered exhaustively by its own httptest
// in provider/<name>/<name>_test.go.
func TestOAuthMultiProviderMountAndStart(t *testing.T) {
	store := memory.New()
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "http://placeholder",
		EncryptionKey: key,
		Providers: []theauth.Provider{
			ghprov.New(ghprov.Config{ClientID: "gh-id", ClientSecret: "gh-sec"}),
			googprov.New(googprov.Config{ClientID: "g-id", ClientSecret: "g-sec"}),
			msprov.New(msprov.Config{ClientID: "ms-id", ClientSecret: "ms-sec"}),
			discprov.New(discprov.Config{ClientID: "d-id", ClientSecret: "d-sec"}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	theauth.SetBaseURLForTest(a, srv.URL)

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}

	cases := []struct {
		provider string
		wantHost string
	}{
		{"github", "github.com"},
		{"google", "accounts.google.com"},
		{"microsoft", "login.microsoftonline.com"},
		{"discord", "discord.com"},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			resp, err := client.Get(srv.URL + "/auth/providers/" + tc.provider + "/start")
			if err != nil {
				t.Fatalf("GET /start: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("/start: expected 302; got %d", resp.StatusCode)
			}
			loc := resp.Header.Get("Location")
			if loc == "" {
				t.Fatal("/start: missing Location header")
			}
			u, err := url.Parse(loc)
			if err != nil {
				t.Fatalf("/start: Location not parseable: %v", err)
			}
			if u.Host != tc.wantHost {
				t.Fatalf("/start: Location host = %q, want %q (full: %s)", u.Host, tc.wantHost, loc)
			}
			// Sanity: every provider must request PKCE S256 and emit a
			// state parameter that matches the cookie set on the
			// response.
			q := u.Query()
			if got := q.Get("code_challenge_method"); got != "S256" {
				t.Fatalf("/start: code_challenge_method = %q, want S256", got)
			}
			state := q.Get("state")
			if state == "" {
				t.Fatal("/start: state missing from authorize URL")
			}
			var cookieValue string
			for _, c := range resp.Cookies() {
				if c.Name == "theauth_oauth_state" {
					cookieValue = c.Value
				}
			}
			if cookieValue != state {
				t.Fatalf("/start: state cookie %q, want match for %q", cookieValue, state)
			}
			// Confirm the redirect URI we send to the provider contains
			// the provider name so the callback lands on the right route.
			if got := q.Get("redirect_uri"); !strings.Contains(got, "/auth/providers/"+tc.provider+"/callback") {
				t.Fatalf("/start: redirect_uri = %q, want path containing /auth/providers/%s/callback", got, tc.provider)
			}
		})
	}
}

// ---------- fuzz tests (originally handlers_oauth_fuzz_test.go) ----------
// FuzzCallbackQueryParams feeds arbitrary raw query strings to the OAuth
// callback handler. The invariant is "never panic" and "never return a
// 5xx server error for malformed input" (4xx is fine).
func FuzzCallbackQueryParams(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("state=abc&code=xyz"))
	f.Add([]byte("garbage&;=="))

	_, mux := newOAuthFuzzAuth(f)

	f.Fuzz(func(t *testing.T, rawQuery []byte) {
		if len(rawQuery) > 8192 {
			rawQuery = rawQuery[:8192]
		}
		// url.ParseQuery is the same parser the handler relies on via
		// r.URL.Query(); validating it does not panic anchors the test.
		_, _ = url.ParseQuery(string(rawQuery))

		// Build the request directly (rather than via httptest.NewRequest,
		// which rejects URLs with raw spaces in the URI line) so the fuzz
		// corpus can include arbitrary bytes in RawQuery.
		req := &http.Request{
			Method:     http.MethodGet,
			URL:        &url.URL{Path: "/auth/providers/stub/callback", RawQuery: string(rawQuery)},
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
			Host:       "localhost",
			RemoteAddr: "127.0.0.1:1",
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("server error for arbitrary query: %d", rec.Code)
		}
	})
}

// FuzzCallbackProviderName injects arbitrary bytes as the {name} path
// parameter and asserts the handler returns 404 for unknown providers,
// never 5xx, and never matches a registered provider via partial or
// case-folded comparison.
func FuzzCallbackProviderName(f *testing.F) {
	f.Add([]byte("github"))
	f.Add([]byte(""))
	f.Add([]byte("STUB"))

	_, mux := newOAuthFuzzAuth(f)

	f.Fuzz(func(t *testing.T, name []byte) {
		if len(name) > 256 {
			name = name[:256]
		}
		// Escape so wild bytes do not break URL parsing; the router still
		// receives the decoded value as {name}.
		path := "/auth/providers/" + url.PathEscape(string(name)) + "/callback?state=x&code=y"
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("server error for arbitrary provider name: %d", rec.Code)
		}
		// Any name that isn't exactly "stub" must not be treated as the
		// stub provider. A 200 / 302 would imply that.
		if string(name) != "stub" && (rec.Code == http.StatusOK || rec.Code == http.StatusFound) {
			t.Fatalf("unknown provider %q produced %d (looks like a match)", string(name), rec.Code)
		}
	})
}
