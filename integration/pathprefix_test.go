package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	ghprov "github.com/glincker/theauth-go/v2/provider/github"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

type captureSender struct {
	mu   sync.Mutex
	body string
}

func (c *captureSender) Send(_ context.Context, _, _, body string) error {
	c.mu.Lock()
	c.body = body
	c.mu.Unlock()
	return nil
}

func (c *captureSender) last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.body
}

func newPrefixServer(t *testing.T, prefix string) (*httptest.Server, *theauth.TheAuth, *captureSender) {
	t.Helper()
	snd := &captureSender{}
	key := make([]byte, 32)
	a, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", PathPrefix: prefix,
		EmailSender: snd, EncryptionKey: key,
		SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
		Providers: []theauth.Provider{ghprov.New(ghprov.Config{ClientID: "cid", ClientSecret: "sec"})},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	mux := http.NewServeMux()
	mux.Handle("/", a.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, a, snd
}

func TestPathPrefixValidation(t *testing.T) {
	tests := []struct {
		prefix  string
		wantErr bool
	}{
		{"", false},
		{"/auth", false},
		{"/api/v1/auth", false},
		{"/a_b-c.d", false},
		{"auth", true},
		{"/", true},
		{"/auth/", true},
		{"/auth?x=1", true},
		{"/auth#frag", true},
		{"/a b", true},
		{"/a//b", true},
		{"/a/../b", true},
		{"/a/{id}", true},
		{"/a/*", true},
	}
	for _, tc := range tests {
		t.Run(tc.prefix, func(t *testing.T) {
			a, err := theauth.New(theauth.Config{Storage: memory.New(), BaseURL: "http://localhost", PathPrefix: tc.prefix})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if a != nil {
				a.Close()
			}
		})
	}
}

func TestCustomPathPrefixEndToEnd(t *testing.T) {
	const p = "/api/v1/auth"
	srv, _, snd := newPrefixServer(t, p)

	resp, _ := postJSON(t, srv, p+"/email-password/signup", map[string]string{"email": "p@x.test", "password": "correct horse battery staple 42"}, nil)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("signup: %d", resp.StatusCode)
	}
	resp, _ = postJSON(t, srv, p+"/email-password/signin", map[string]string{"email": "p@x.test", "password": "correct horse battery staple 42"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signin: %d", resp.StatusCode)
	}
	cookies := resp.Cookies()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+p+"/me", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	me, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = me.Body.Close()
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me: %d", me.StatusCode)
	}

	old, err := http.Get(srv.URL + "/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	_ = old.Body.Close()
	if old.StatusCode != http.StatusNotFound {
		t.Fatalf("canonical path must not serve under a custom prefix: %d", old.StatusCode)
	}

	resp, _ = postJSON(t, srv, p+"/magic-link", map[string]string{"email": "m@x.test"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("magic-link: %d", resp.StatusCode)
	}
	if body := snd.last(); !strings.Contains(body, "http://localhost"+p+"/magic-link/verify?token=") {
		t.Fatalf("magic link missing prefix: %q", body)
	}

	resp, _ = postJSON(t, srv, p+"/email-password/forgot", map[string]string{"email": "p@x.test"}, nil)
	if resp.StatusCode >= 500 {
		t.Fatalf("forgot: %d", resp.StatusCode)
	}
	if body := snd.last(); !strings.Contains(body, p+"/email-password/reset?token=") {
		t.Fatalf("reset link missing prefix: %q", body)
	}
}

func TestOAuthRedirectURIUsesPrefix(t *testing.T) {
	tests := []struct {
		name, prefix, want string
	}{
		{"default", "", "/auth/providers/github/callback"},
		{"custom", "/api/v1/auth", "/api/v1/auth/providers/github/callback"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := newPrefixServer(t, tc.prefix)
			prefix := tc.prefix
			if prefix == "" {
				prefix = "/auth"
			}
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			resp, err := client.Get(srv.URL + prefix + "/providers/github/start")
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("start: %d", resp.StatusCode)
			}
			u, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if got := u.Query().Get("redirect_uri"); got != "http://localhost"+tc.want {
				t.Fatalf("redirect_uri = %q, want %q", got, "http://localhost"+tc.want)
			}
		})
	}
}
