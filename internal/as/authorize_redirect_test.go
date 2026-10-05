package as_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/glincker/theauth-go/v2/crypto"
)

func TestAuthorizeErrorRedirectOnlyToRegisteredURI(t *testing.T) {
	_, srv, _, _ := newASHarness(t)
	client := registerTestClient(t, srv)
	verifier, _ := crypto.NewCodeVerifier()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	tests := []struct {
		name        string
		clientID    string
		redirectURI string
		wantRedir   bool
	}{
		{"registered uri gets error redirect", client.ClientID, "https://app.example.com/cb", true},
		{"attacker uri is never redirected to", client.ClientID, "https://evil.example.net/steal", false},
		{"prefix of registered uri is not a match", client.ClientID, "https://app.example.com/cb/../x", false},
		{"unknown client is never redirected", "no-such-client", "https://evil.example.net/steal", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{}
			q.Set("response_type", "token")
			q.Set("client_id", tc.clientID)
			q.Set("redirect_uri", tc.redirectURI)
			q.Set("state", "xyz")
			q.Set("code_challenge", crypto.CodeChallenge(verifier))
			q.Set("code_challenge_method", "S256")
			resp, err := noFollow.Get(srv.URL + "/oauth/authorize?" + q.Encode())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if tc.wantRedir {
				if resp.StatusCode != http.StatusFound {
					t.Fatalf("status = %d, want 302", resp.StatusCode)
				}
				loc, _ := url.Parse(resp.Header.Get("Location"))
				if loc == nil || loc.Host != "app.example.com" || loc.Query().Get("error") != "unsupported_response_type" {
					t.Fatalf("Location = %q", resp.Header.Get("Location"))
				}
				return
			}
			if resp.StatusCode == http.StatusFound || resp.Header.Get("Location") != "" {
				t.Fatalf("must not redirect, got %d Location=%q", resp.StatusCode, resp.Header.Get("Location"))
			}
		})
	}
}
