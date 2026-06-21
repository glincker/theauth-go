package theauth_test

import (
	"crypto/rand"
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
