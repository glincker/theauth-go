package integration

import (
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/integration/internal/testutil"
	ghprov "github.com/glincker/theauth-go/v2/provider/github"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

type redirectFixture struct {
	srv *httptest.Server
	a   *theauth.TheAuth

	mu       sync.Mutex
	exchange []string
}

func (f *redirectFixture) exchanged() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.exchange...)
}

func newRedirectFixture(t *testing.T, cfg *theauth.OAuthConfig) *redirectFixture {
	t.Helper()
	f := &redirectFixture{}
	mock := mockGitHubServer(t, "gho_x", "redir@example.com", 77)
	rec := http.NewServeMux()
	rec.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.exchange = append(f.exchange, r.PostForm.Get("redirect_uri"))
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_x","token_type":"bearer"}`))
	})
	tok := httptest.NewServer(rec)
	t.Cleanup(tok.Close)

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	a, err := theauth.New(theauth.Config{
		Storage:           memory.New(),
		BaseURL:           "http://placeholder",
		EncryptionKey:     key,
		PostLoginRedirect: "/after-login",
		OAuth:             cfg,
		RateLimitPerIP:    1000,
		Providers: []theauth.Provider{ghprov.New(ghprov.Config{
			ClientID: "cid", ClientSecret: "csec",
			TokenURL: tok.URL + "/token", UserURL: mock.URL + "/user",
			EmailsURL: mock.URL + "/user/emails", AuthorizeURL: mock.URL + "/login/oauth/authorize",
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	f.srv = httptest.NewServer(r)
	testutil.SetBaseURLForTest(a, f.srv.URL)
	f.a = a
	t.Cleanup(func() { f.srv.Close(); a.Close() })
	return f
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func stateCookieOf(resp *http.Response) *http.Cookie {
	for _, ck := range resp.Cookies() {
		if ck.Name == "theauth_oauth_state" {
			return ck
		}
	}
	return nil
}

func (f *redirectFixture) start(t *testing.T, query string) (*http.Response, url.Values, *http.Cookie) {
	t.Helper()
	resp, err := noRedirect().Get(f.srv.URL + "/auth/providers/github/start" + query)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	var q url.Values
	if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode == http.StatusFound {
		u, _ := url.Parse(loc)
		q = u.Query()
	}
	return resp, q, stateCookieOf(resp)
}

func (f *redirectFixture) callback(t *testing.T, state string, c *http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", f.srv.URL+"/auth/providers/github/callback?code=c&state="+url.QueryEscape(state), nil)
	req.AddCookie(c)
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func redirectHook(uri string) *theauth.OAuthConfig {
	return &theauth.OAuthConfig{RedirectURI: func(*http.Request, string) (string, error) { return uri, nil }}
}

func TestOAuthRedirectURIHook(t *testing.T) {
	const custom = "https://app.example.com/api/v1/auth/oauth/github/callback"
	tests := []struct {
		name     string
		cfg      *theauth.OAuthConfig
		wantURI  string
		wantFail bool
	}{
		{"default unchanged", nil, "", false},
		{"custom https", redirectHook(custom), custom, false},
		{"custom with allowed host", &theauth.OAuthConfig{
			RedirectURI:             redirectHook(custom).RedirectURI,
			RedirectURIAllowedHosts: []string{"APP.example.com"},
		}, custom, false},
		{"loopback http allowed", redirectHook("http://127.0.0.1:3000/cb"), "http://127.0.0.1:3000/cb", false},
		{"http with opt in", &theauth.OAuthConfig{
			AllowInsecureRedirectURI: true,
			RedirectURI:              redirectHook("http://app.example.com/cb").RedirectURI,
		}, "http://app.example.com/cb", false},
		{"relative", redirectHook("/cb"), "", true},
		{"javascript scheme", redirectHook("javascript:alert(1)"), "", true},
		{"fragment", redirectHook("https://app.example.com/cb#x"), "", true},
		{"userinfo", redirectHook("https://user:pw@app.example.com/cb"), "", true},
		{"http non loopback", redirectHook("http://app.example.com/cb"), "", true},
		{"backslash", redirectHook("https://app.example.com\\@evil.test/cb"), "", true},
		{"host not in allow list", &theauth.OAuthConfig{
			RedirectURI:             redirectHook("https://evil.test/cb").RedirectURI,
			RedirectURIAllowedHosts: []string{"app.example.com"},
		}, "", true},
		{"hook error", &theauth.OAuthConfig{
			RedirectURI: func(*http.Request, string) (string, error) { return "", errors.New("boom") },
		}, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRedirectFixture(t, tc.cfg)
			resp, q, cookie := f.start(t, "")
			if tc.wantFail {
				if resp.StatusCode != http.StatusInternalServerError {
					t.Fatalf("status = %d, want 500", resp.StatusCode)
				}
				if cookie != nil || resp.Header.Get("Location") != "" {
					t.Fatalf("fail closed violated: cookie=%v location=%q", cookie, resp.Header.Get("Location"))
				}
				return
			}
			want := tc.wantURI
			if want == "" {
				want = "http://placeholder/auth/providers/github/callback"
			}
			if got := q.Get("redirect_uri"); got != want {
				t.Fatalf("authorize redirect_uri = %q, want %q", got, want)
			}
			r2 := f.callback(t, q.Get("state"), cookie)
			if r2.StatusCode != http.StatusFound || r2.Header.Get("Location") != "/after-login" {
				t.Fatalf("callback = %d %q", r2.StatusCode, r2.Header.Get("Location"))
			}
			if ex := f.exchanged(); len(ex) != 1 || ex[0] != want {
				t.Fatalf("exchange redirect_uri = %v, want [%q]", ex, want)
			}
		})
	}
}

func TestOAuthRedirectURIConcurrentStartsDoNotLeak(t *testing.T) {
	f := newRedirectFixture(t, &theauth.OAuthConfig{
		RedirectURIAllowedHosts: []string{"a.example.com", "b.example.com"},
		RedirectURI: func(r *http.Request, p string) (string, error) {
			return "https://" + r.URL.Query().Get("h") + "/cb/" + p, nil
		},
	})
	type out struct {
		q      url.Values
		cookie *http.Cookie
		host   string
	}
	const n = 24
	res := make([]out, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := "a.example.com"
			if i%2 == 1 {
				h = "b.example.com"
			}
			resp, err := noRedirect().Get(f.srv.URL + "/auth/providers/github/start?h=" + h)
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
			u, _ := url.Parse(resp.Header.Get("Location"))
			res[i] = out{q: u.Query(), cookie: stateCookieOf(resp), host: h}
		}()
	}
	wg.Wait()
	for i, o := range res {
		if o.q == nil {
			t.Fatalf("start %d failed", i)
		}
		want := "https://" + o.host + "/cb/github"
		if got := o.q.Get("redirect_uri"); got != want {
			t.Fatalf("start %d redirect_uri = %q, want %q", i, got, want)
		}
		if r2 := f.callback(t, o.q.Get("state"), o.cookie); r2.StatusCode != http.StatusFound {
			t.Fatalf("callback %d = %d", i, r2.StatusCode)
		}
	}
	seen := map[string]int{}
	for _, ex := range f.exchanged() {
		seen[ex]++
	}
	if seen["https://a.example.com/cb/github"] != n/2 || seen["https://b.example.com/cb/github"] != n/2 || len(seen) != 2 {
		t.Fatalf("exchange URIs leaked between states: %v", seen)
	}
}

func TestOAuthProgrammaticStartCallback(t *testing.T) {
	const custom = "https://app.example.com/api/v1/auth/oauth/github/callback"
	f := newRedirectFixture(t, redirectHook(custom))
	sr, err := f.a.OAuthStart(httptest.NewRequest("GET", "/own/start", nil), "github", "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(sr.AuthURL)
	if got := u.Query().Get("redirect_uri"); got != custom {
		t.Fatalf("authorize redirect_uri = %q", got)
	}
	res, user, err := f.a.OAuthCallback(httptest.NewRequest("GET", "/api/v1/auth/oauth/github/callback", nil), "github", "code", sr.State, sr.Binding)
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionToken == "" || user == nil || !strings.EqualFold(user.Email, "redir@example.com") {
		t.Fatalf("unexpected result %+v %+v", res, user)
	}
	if ex := f.exchanged(); len(ex) != 1 || ex[0] != custom {
		t.Fatalf("exchange = %v", ex)
	}
}
