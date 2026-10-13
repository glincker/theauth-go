package integration

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

// refreshingProvider is a Provider that hands out short-lived tokens and
// supports the refresh grant.
type refreshingProvider struct {
	name      string
	user      theauth.ProviderUser
	expiresIn time.Duration
	noRefresh bool // sign-in returns no refresh token

	calls   atomic.Int32
	revoked atomic.Bool
	delay   time.Duration
	mu      sync.Mutex
	rotated int
}

func (p *refreshingProvider) Name() string { return p.name }

func (p *refreshingProvider) AuthURL(state, challenge, _ string, _ []string) string {
	return "https://idp.example/authorize?" + url.Values{"state": {state}, "code_challenge": {challenge}}.Encode()
}

func (p *refreshingProvider) ExchangeCode(context.Context, string, string, string) (*theauth.ProviderToken, error) {
	tok := &theauth.ProviderToken{AccessToken: "at-0", ExpiresAt: time.Now().Add(p.expiresIn), Scope: "read"}
	if !p.noRefresh {
		tok.RefreshToken = "rt-0"
	}
	return tok, nil
}

func (p *refreshingProvider) UserInfo(context.Context, *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	u := p.user
	return &u, nil
}

func (p *refreshingProvider) RefreshToken(_ context.Context, refreshToken string) (*theauth.ProviderToken, error) {
	p.calls.Add(1)
	time.Sleep(p.delay)
	if p.revoked.Load() {
		return nil, errors.Join(errors.New("upstream said no"), theauth.ErrProviderGrantRevoked)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rotated++
	return &theauth.ProviderToken{
		AccessToken:  "at-" + string(rune('0'+p.rotated)),
		RefreshToken: "rt-" + string(rune('0'+p.rotated)),
		ExpiresAt:    time.Now().Add(time.Hour),
	}, nil
}

// plainProvider has no RefreshToken method.
type plainProvider struct{ refreshingProvider }

func (p *plainProvider) RefreshToken() {} // wrong signature on purpose: not a RefreshProvider

func ptSetup(t *testing.T, prov theauth.Provider, email string) (*theauth.TheAuth, *memory.Store, theauth.ULID) {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", EncryptionKey: key,
		Providers: []theauth.Provider{prov}, RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mountedHandler(a))
	t.Cleanup(func() { srv.Close(); a.Close() })

	resp, err := noFollow.Get(srv.URL + "/auth/providers/" + prov.Name() + "/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "theauth_oauth_state" {
			cookie = c
		}
	}
	req, _ := http.NewRequest("GET", srv.URL+"/auth/providers/"+prov.Name()+"/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil)
	req.AddCookie(cookie)
	cb, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = cb.Body.Close()
	if cb.StatusCode != http.StatusFound {
		t.Fatalf("callback status %d", cb.StatusCode)
	}
	u, err := store.UserByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return a, store, u.ID
}

func TestGetProviderTokenReturnsValidTokenWithoutRefresh(t *testing.T) {
	prov := &refreshingProvider{name: "rp", expiresIn: time.Hour, user: theauth.ProviderUser{ID: "1", Email: "pt1@x.com", EmailVerified: true}}
	a, _, uid := ptSetup(t, prov, "pt1@x.com")
	tok, err := a.GetProviderToken(context.Background(), uid, "rp")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at-0" || tok.Scope != "read" || tok.ExpiresAt.IsZero() {
		t.Fatalf("token = %+v", tok)
	}
	if prov.calls.Load() != 0 {
		t.Fatalf("refresh calls = %d, want 0", prov.calls.Load())
	}
}

func TestGetProviderTokenRefreshesExpiredAndPersists(t *testing.T) {
	prov := &refreshingProvider{name: "rp", expiresIn: -time.Minute, user: theauth.ProviderUser{ID: "2", Email: "pt2@x.com", EmailVerified: true}}
	a, store, uid := ptSetup(t, prov, "pt2@x.com")
	ctx := context.Background()

	tok, err := a.GetProviderToken(ctx, uid, "rp")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at-1" || tok.RefreshToken != "rt-1" {
		t.Fatalf("token = %+v", tok)
	}
	// The next call is served from storage: the persisted token is valid.
	tok2, err := a.GetProviderToken(ctx, uid, "rp")
	if err != nil || tok2.AccessToken != "at-1" {
		t.Fatalf("second call = %+v, %v", tok2, err)
	}
	if prov.calls.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", prov.calls.Load())
	}
	// Tokens are stored encrypted.
	accts, _ := store.OAuthAccountsByUserID(ctx, uid)
	if len(accts) != 1 || string(accts[0].AccessTokenEnc) == "at-1" || len(accts[0].RefreshTokenEnc) == 0 {
		t.Fatalf("stored account = %+v", accts)
	}
}

func TestGetProviderTokenSingleFlight(t *testing.T) {
	prov := &refreshingProvider{name: "rp", expiresIn: -time.Minute, delay: 150 * time.Millisecond,
		user: theauth.ProviderUser{ID: "3", Email: "pt3@x.com", EmailVerified: true}}
	a, _, uid := ptSetup(t, prov, "pt3@x.com")
	var wg sync.WaitGroup
	results := make([]string, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := a.GetProviderToken(context.Background(), uid, "rp")
			if err != nil {
				results[i] = "err:" + err.Error()
				return
			}
			results[i] = tok.AccessToken
		}()
	}
	wg.Wait()
	if prov.calls.Load() != 1 {
		t.Fatalf("upstream refresh calls = %d, want 1 for 8 concurrent callers", prov.calls.Load())
	}
	for i, r := range results {
		if r != "at-1" {
			t.Errorf("caller %d got %q", i, r)
		}
	}
}

func TestGetProviderTokenGrantRevokedClearsTokens(t *testing.T) {
	prov := &refreshingProvider{name: "rp", expiresIn: -time.Minute, user: theauth.ProviderUser{ID: "4", Email: "pt4@x.com", EmailVerified: true}}
	a, store, uid := ptSetup(t, prov, "pt4@x.com")
	ctx := context.Background()
	prov.revoked.Store(true)

	_, err := a.GetProviderToken(ctx, uid, "rp")
	if !errors.Is(err, theauth.ErrProviderGrantRevoked) {
		t.Fatalf("err = %v, want ErrProviderGrantRevoked", err)
	}
	var te *theauth.TheAuthError
	if !errors.As(err, &te) || te.Code != theauth.CodeProviderGrantRevoked {
		t.Fatalf("want code %s, got %v", theauth.CodeProviderGrantRevoked, err)
	}
	accts, _ := store.OAuthAccountsByUserID(ctx, uid)
	if len(accts) != 1 || len(accts[0].AccessTokenEnc) != 0 || len(accts[0].RefreshTokenEnc) != 0 {
		t.Fatalf("revoked grant must clear stored tokens, got %+v", accts)
	}
	// A repeat call fails fast without another upstream round trip.
	before := prov.calls.Load()
	if _, err := a.GetProviderToken(ctx, uid, "rp"); !errors.Is(err, theauth.ErrProviderGrantRevoked) {
		t.Fatalf("repeat err = %v", err)
	}
	if prov.calls.Load() != before {
		t.Fatal("repeat call must not hit the provider")
	}
}

func TestGetProviderTokenNoRefreshToken(t *testing.T) {
	prov := &refreshingProvider{name: "rp", expiresIn: -time.Minute, noRefresh: true, user: theauth.ProviderUser{ID: "5", Email: "pt5@x.com", EmailVerified: true}}
	a, _, uid := ptSetup(t, prov, "pt5@x.com")
	_, err := a.GetProviderToken(context.Background(), uid, "rp")
	if !errors.Is(err, theauth.ErrProviderRefreshUnsupported) {
		t.Fatalf("err = %v, want ErrProviderRefreshUnsupported", err)
	}
}

func TestGetProviderTokenProviderWithoutRefreshCapability(t *testing.T) {
	prov := &plainProvider{refreshingProvider{name: "plain", expiresIn: -time.Minute, user: theauth.ProviderUser{ID: "6", Email: "pt6@x.com", EmailVerified: true}}}
	a, _, uid := ptSetup(t, prov, "pt6@x.com")
	_, err := a.GetProviderToken(context.Background(), uid, "plain")
	if !errors.Is(err, theauth.ErrProviderRefreshUnsupported) {
		t.Fatalf("err = %v, want ErrProviderRefreshUnsupported", err)
	}
}

func TestGetProviderTokenNotLinked(t *testing.T) {
	prov := &refreshingProvider{name: "rp", expiresIn: time.Hour, user: theauth.ProviderUser{ID: "7", Email: "pt7@x.com", EmailVerified: true}}
	a, _, uid := ptSetup(t, prov, "pt7@x.com")
	if _, err := a.GetProviderToken(context.Background(), uid, "github"); !errors.Is(err, theauth.ErrProviderNotLinked) {
		t.Fatalf("err = %v, want ErrProviderNotLinked", err)
	}
}

func TestOAuthRelinkKeepsStoredRefreshToken(t *testing.T) {
	// A second sign-in that brings no refresh token (as Google does after the
	// first consent) must not erase the stored one.
	prov := &refreshingProvider{name: "rp", expiresIn: time.Hour, user: theauth.ProviderUser{ID: "8", Email: "pt8@x.com", EmailVerified: true}}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", EncryptionKey: key,
		Providers: []theauth.Provider{prov}, RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mountedHandler(a))
	defer func() { srv.Close(); a.Close() }()
	login := func() {
		resp, _ := noFollow.Get(srv.URL + "/auth/providers/rp/start")
		_ = resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		var cookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "theauth_oauth_state" {
				cookie = c
			}
		}
		req, _ := http.NewRequest("GET", srv.URL+"/auth/providers/rp/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil)
		req.AddCookie(cookie)
		cb, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = cb.Body.Close()
	}
	login()
	prov.noRefresh = true
	login()
	u, _ := store.UserByEmail(context.Background(), "pt8@x.com")
	accts, _ := store.OAuthAccountsByUserID(context.Background(), u.ID)
	if len(accts) != 1 || len(accts[0].RefreshTokenEnc) == 0 {
		t.Fatalf("refresh token lost on relink: %+v", accts)
	}
}
