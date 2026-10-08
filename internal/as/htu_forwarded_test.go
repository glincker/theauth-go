package as_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"context"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
)

// The DPoP htu is built from the configured issuer; forwarded headers
// must not influence it.
func TestTokenEndpointHTUIgnoresForwardedHeaders(t *testing.T) {
	tests := []struct {
		name       string
		htu        func(srvURL string) string
		wantStatus int
	}{
		{"proof for forwarded origin rejected", func(string) string { return "https://evil.example.net/oauth/token" }, http.StatusBadRequest},
		{"proof for request host rejected", func(srv string) string { return srv + "/oauth/token" }, http.StatusBadRequest},
		{"proof for issuer accepted", func(string) string { return "https://auth.example.com/oauth/token" }, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, srv, user := newDPoPHarness(t)
			defer srv.Close()
			client := registerTestClient(t, srv)
			verifier, _ := crypto.NewCodeVerifier()
			res, err := a.StartAuthorize(context.Background(), theauth.AuthorizeRequest{
				ClientID: client.ClientID, RedirectURI: "https://app.example.com/cb", ResponseType: "code",
				Scope: []string{"files.read"}, CodeChallenge: crypto.CodeChallenge(verifier),
				CodeChallengeMethod: "S256", Resource: "https://files.example.com/mcp",
			}, &user)
			if err != nil {
				t.Fatal(err)
			}
			form := url.Values{
				"grant_type": {theauth.GrantTypeAuthorizationCode}, "client_id": {client.ClientID},
				"client_secret": {client.ClientSecret}, "code": {codeFromRedirect(t, res.RedirectURL)},
				"code_verifier": {verifier}, "redirect_uri": {"https://app.example.com/cb"},
			}
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", "evil.example.net")
			req.Header.Set("DPoP", makeDPoPProof(t, newP256(t), "POST", tc.htu(srv.URL), "", time.Now()))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status %d want %d", resp.StatusCode, tc.wantStatus)
			}
		})
	}
}
