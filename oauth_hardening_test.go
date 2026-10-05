package theauth_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

type hardenProvider struct {
	mu       sync.Mutex
	user     theauth.ProviderUser
	verifier string
}

func (p *hardenProvider) Name() string { return "hard" }

func (p *hardenProvider) AuthURL(state, challenge, redirectURI string, _ []string) string {
	return "https://idp.example/authorize?" + url.Values{
		"state": {state}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()
}

func (p *hardenProvider) ExchangeCode(_ context.Context, _, verifier, _ string) (*theauth.ProviderToken, error) {
	p.mu.Lock()
	p.verifier = verifier
	p.mu.Unlock()
	return &theauth.ProviderToken{AccessToken: "tok"}, nil
}

func (p *hardenProvider) UserInfo(context.Context, *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	u := p.user
	return &u, nil
}

type countingStore struct {
	inner       theauth.OAuthStateStore
	puts, takes int
}

func (c *countingStore) Put(ctx context.Context, k string, st theauth.OAuthState, ttl time.Duration) error {
	c.puts++
	return c.inner.Put(ctx, k, st, ttl)
}

func (c *countingStore) Take(ctx context.Context, k string) (theauth.OAuthState, error) {
	c.takes++
	return c.inner.Take(ctx, k)
}

func newHardenServer(t *testing.T, prov *hardenProvider, oc *theauth.OAuthConfig) (*httptest.Server, *memory.Store) {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", EncryptionKey: key,
		PostLoginRedirect: "/home", Providers: []theauth.Provider{prov}, OAuth: oc,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(func() { srv.Close(); a.Close() })
	return srv, store
}

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func startFlow(t *testing.T, srv *httptest.Server, query string) (state, challenge string, cookie *http.Cookie) {
	t.Helper()
	resp, err := noFollow.Get(srv.URL + "/auth/providers/hard/start" + query)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	u, _ := url.Parse(resp.Header.Get("Location"))
	for _, c := range resp.Cookies() {
		if c.Name == "theauth_oauth_state" {
			cookie = c
		}
	}
	return u.Query().Get("state"), u.Query().Get("code_challenge"), cookie
}

func callback(t *testing.T, srv *httptest.Server, state string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+"/auth/providers/hard/callback?code=c&state="+url.QueryEscape(state), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func TestOAuthLoginCSRFRejected(t *testing.T) {
	prov := &hardenProvider{user: theauth.ProviderUser{ID: "1", Email: "a@x.com", EmailVerified: true}}
	srv, _ := newHardenServer(t, prov, nil)

	attackerState, _, attackerCookie := startFlow(t, srv, "")
	_, _, victimCookie := startFlow(t, srv, "")

	if resp := callback(t, srv, attackerState, victimCookie); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("attacker state with victim cookie: want 400 got %d", resp.StatusCode)
	}
	// The state is burned by the failed attempt, so even the real cookie cannot replay it.
	if resp := callback(t, srv, attackerState, attackerCookie); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("burned state: want 400 got %d", resp.StatusCode)
	}
	state, _, _ := startFlow(t, srv, "")
	if resp := callback(t, srv, state, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("no binding cookie: want 400 got %d", resp.StatusCode)
	}
}

func TestOAuthPKCEVerifierMatchesChallenge(t *testing.T) {
	prov := &hardenProvider{user: theauth.ProviderUser{ID: "1", Email: "a@x.com", EmailVerified: true}}
	srv, _ := newHardenServer(t, prov, nil)
	state, challenge, cookie := startFlow(t, srv, "")
	if challenge == "" {
		t.Fatal("authorize URL must carry a PKCE challenge")
	}
	if resp := callback(t, srv, state, cookie); resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	if got := theauth.OAuthCodeChallengeForTest(prov.verifier); got != challenge {
		t.Fatalf("verifier does not match challenge: %q vs %q", got, challenge)
	}
}

func TestOAuthReturnToAllowList(t *testing.T) {
	prov := &hardenProvider{user: theauth.ProviderUser{ID: "1", Email: "a@x.com", EmailVerified: true}}
	srv, _ := newHardenServer(t, prov, &theauth.OAuthConfig{AllowedReturnTo: []string{"/dash", "/app/*", "https://app.example.com/ok"}})
	cases := []struct{ q, want string }{
		{"?return_to=/dash", "/dash"},
		{"?return_to=/app/x/y", "/app/x/y"},
		{"?return_to=https://app.example.com/ok", "https://app.example.com/ok"},
		{"?return_to=https://evil.example.com/", "/home"},
		{"?return_to=//evil.example.com", "/home"},
		{"?return_to=/dashboard", "/home"},
		{"", "/home"},
	}
	for _, c := range cases {
		state, _, cookie := startFlow(t, srv, c.q)
		resp := callback(t, srv, state, cookie)
		if got := resp.Header.Get("Location"); got != c.want {
			t.Errorf("%q: redirect %q want %q", c.q, got, c.want)
		}
	}
}

func TestOAuthSignupPolicy(t *testing.T) {
	cases := []struct {
		name      string
		cfg       *theauth.OAuthConfig
		user      theauth.ProviderUser
		wantCode  int
		wantUser  bool
		wantEmail string
	}{
		{"default open", nil, theauth.ProviderUser{ID: "1", Email: "n@any.com", EmailVerified: true}, 302, true, "n@any.com"},
		{"closed", &theauth.OAuthConfig{Signup: theauth.OAuthSignupClosed}, theauth.ProviderUser{ID: "1", Email: "n@any.com", EmailVerified: true}, 400, false, "n@any.com"},
		{"domain ok", &theauth.OAuthConfig{Signup: theauth.OAuthSignupAllowedDomains, AllowedEmailDomains: []string{"corp.com"}}, theauth.ProviderUser{ID: "1", Email: "N@Corp.com", EmailVerified: true}, 302, true, "n@corp.com"},
		{"domain refused", &theauth.OAuthConfig{Signup: theauth.OAuthSignupAllowedDomains, AllowedEmailDomains: []string{"corp.com"}}, theauth.ProviderUser{ID: "1", Email: "n@evil.com", EmailVerified: true}, 400, false, "n@evil.com"},
		{"domain unverified refused", &theauth.OAuthConfig{Signup: theauth.OAuthSignupAllowedDomains, AllowedEmailDomains: []string{"corp.com"}}, theauth.ProviderUser{ID: "1", Email: "n@corp.com"}, 400, false, "n@corp.com"},
		{"domain suffix trick refused", &theauth.OAuthConfig{Signup: theauth.OAuthSignupAllowedDomains, AllowedEmailDomains: []string{"corp.com"}}, theauth.ProviderUser{ID: "1", Email: "n@evilcorp.com", EmailVerified: true}, 400, false, "n@evilcorp.com"},
		{"invite ok", &theauth.OAuthConfig{Signup: theauth.OAuthSignupInvite, InviteCheck: func(_ context.Context, e string) (bool, error) { return e == "n@any.com", nil }}, theauth.ProviderUser{ID: "1", Email: "n@any.com", EmailVerified: true}, 302, true, "n@any.com"},
		{"invite refused", &theauth.OAuthConfig{Signup: theauth.OAuthSignupInvite, InviteCheck: func(context.Context, string) (bool, error) { return false, nil }}, theauth.ProviderUser{ID: "1", Email: "n@any.com", EmailVerified: true}, 400, false, "n@any.com"},
		{"invite without checker refused", &theauth.OAuthConfig{Signup: theauth.OAuthSignupInvite}, theauth.ProviderUser{ID: "1", Email: "n@any.com", EmailVerified: true}, 400, false, "n@any.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prov := &hardenProvider{user: c.user}
			srv, store := newHardenServer(t, prov, c.cfg)
			state, _, cookie := startFlow(t, srv, "")
			if resp := callback(t, srv, state, cookie); resp.StatusCode != c.wantCode {
				t.Fatalf("status %d want %d", resp.StatusCode, c.wantCode)
			}
			_, err := store.UserByEmail(context.Background(), c.wantEmail)
			if (err == nil) != c.wantUser {
				t.Fatalf("user exists=%v want %v (err %v)", err == nil, c.wantUser, err)
			}
		})
	}
}

func TestOAuthUnverifiedEmailCannotLinkExistingAccount(t *testing.T) {
	prov := &hardenProvider{user: theauth.ProviderUser{ID: "9", Email: "victim@x.com", EmailVerified: false}}
	srv, store := newHardenServer(t, prov, nil)
	if _, _, err := theauth.SignupWithPasswordForTestStore(store, "victim@x.com"); err != nil {
		t.Fatal(err)
	}
	state, _, cookie := startFlow(t, srv, "")
	if resp := callback(t, srv, state, cookie); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unverified email match must be refused, got %d", resp.StatusCode)
	}
	if _, err := store.OAuthAccountByProviderUserID(context.Background(), "hard", "9"); err == nil {
		t.Fatal("oauth account must not be linked")
	}
}

func TestOAuthCaseInsensitiveEmailLinksSameAccount(t *testing.T) {
	prov := &hardenProvider{user: theauth.ProviderUser{ID: "9", Email: "Mixed@X.com", EmailVerified: true}}
	srv, store := newHardenServer(t, prov, nil)
	existing, _, err := theauth.SignupWithPasswordForTestStore(store, "mixed@x.com")
	if err != nil {
		t.Fatal(err)
	}
	state, _, cookie := startFlow(t, srv, "")
	if resp := callback(t, srv, state, cookie); resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	acct, err := store.OAuthAccountByProviderUserID(context.Background(), "hard", "9")
	if err != nil || acct.UserID != existing.ID {
		t.Fatalf("must link to the existing account, got %+v err %v", acct, err)
	}
}

func TestOAuthPluggableStateStore(t *testing.T) {
	cs := &countingStore{inner: theauth.NewMemoryOAuthStateStore()}
	prov := &hardenProvider{user: theauth.ProviderUser{ID: "1", Email: "a@x.com", EmailVerified: true}}
	srv, _ := newHardenServer(t, prov, &theauth.OAuthConfig{StateStore: cs})
	state, _, cookie := startFlow(t, srv, "")
	if resp := callback(t, srv, state, cookie); resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	if cs.puts != 1 || cs.takes != 1 {
		t.Fatalf("custom store not used: puts=%d takes=%d", cs.puts, cs.takes)
	}
}

func TestOAuthAuthEvents(t *testing.T) {
	log := &eventLog{}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	prov := &hardenProvider{user: theauth.ProviderUser{ID: "1", Email: "a@x.com", EmailVerified: true}}
	a, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", EncryptionKey: key,
		Providers: []theauth.Provider{prov}, AuthEventSink: log.sink,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(func() { srv.Close(); a.Close() })

	state, _, cookie := startFlow(t, srv, "")
	callback(t, srv, state, &http.Cookie{Name: cookie.Name, Value: "wrong"})
	state, _, cookie = startFlow(t, srv, "")
	callback(t, srv, state, cookie)

	fail := log.find(theauth.AuthEventLoginFailure)
	if len(fail) != 1 || fail[0].Method != "oauth:hard" || fail[0].Reason != "state_binding_mismatch" || fail[0].IPPrefix != "127.0.0.0/24" {
		t.Fatalf("login failure event wrong: %+v", fail)
	}
	if ok := log.find(theauth.AuthEventLoginSuccess); len(ok) != 1 || ok[0].Method != "oauth:hard" || ok[0].UserID == "" {
		t.Fatalf("login success event wrong: %+v", ok)
	}
	if len(log.find(theauth.AuthEventOAuthLinked)) != 1 {
		t.Fatal("oauth.linked event missing")
	}
}
