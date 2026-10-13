package cimd

import (
	"context"
	"strings"
	"testing"
	"time"
)

const cursorRedirect = "cursor://anysphere.cursor-mcp/oauth/callback"

func TestAllowedRedirectSchemesConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		schemes []string
		wantErr bool
	}{
		{"empty is today's behavior", nil, false},
		{"bare vendor scheme", []string{"cursor"}, false},
		{"reverse dns scheme", []string{"com.example.app"}, false},
		{"scheme with digits and dashes", []string{"my-app2"}, false},
		{"uppercase rejected", []string{"Cursor"}, true},
		{"empty entry rejected", []string{""}, true},
		{"http rejected", []string{"http"}, true},
		{"https rejected", []string{"https"}, true},
		{"javascript rejected", []string{"javascript"}, true},
		{"data rejected", []string{"data"}, true},
		{"file rejected", []string{"file"}, true},
		{"not a scheme", []string{"cur sor"}, true},
		{"leading digit", []string{"1app"}, true},
		{"one bad among good", []string{"cursor", "file"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := (&Config{AllowedRedirectSchemes: tc.schemes}).Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestAllowedRedirectSchemesDocumentValidation(t *testing.T) {
	const id = "https://cursor.com/.well-known/oauth-client.json"
	doc := func(redirect string) []byte {
		return []byte(`{"client_id":"` + id + `","client_name":"Cursor","redirect_uris":["` + redirect + `"],"token_endpoint_auth_method":"none"}`)
	}
	tests := []struct {
		name     string
		redirect string
		allowed  []string
		wantErr  string
	}{
		{"bare scheme refused by default", cursorRedirect, nil, "reverse-DNS"},
		{"bare scheme accepted when listed", cursorRedirect, []string{"cursor"}, ""},
		{"listing another scheme does not help", cursorRedirect, []string{"vscode"}, "reverse-DNS"},
		{"listed scheme still refuses fragment", cursorRedirect + "#x", []string{"cursor"}, "fragment"},
		{"listed scheme still refuses userinfo", "cursor://user@anysphere.cursor-mcp/cb", []string{"cursor"}, "userinfo"},
		{"https still fine", "https://cursor.com/cb", []string{"cursor"}, ""},
		{"javascript never fine", "javascript://x/%0aalert(1)", []string{"cursor"}, "not allowed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAndValidate(doc(tc.redirect), id, tc.allowed...)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestServiceHonorsAllowedRedirectSchemes(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, nil)
	ts.setHandler(serveDoc(Document{
		ClientID:                ts.URL(),
		ClientName:              "Cursor",
		RedirectURIs:            []string{cursorRedirect, "http://127.0.0.1:33418/oauth/callback"},
		TokenEndpointAuthMethod: "none",
	}))
	resolve := func(schemes []string) error {
		svc := NewService(Config{
			TrustPolicy: AllowAnyHTTPS(), HTTPClient: trustingClient(2 * time.Second),
			NegativeCacheTTL: -1, AllowedRedirectSchemes: schemes,
		}, nil)
		_, err := svc.Resolve(context.Background(), ts.URL())
		return err
	}
	if err := resolve(nil); err == nil {
		t.Fatal("default config accepted a bare private-use scheme")
	}
	if err := resolve([]string{"cursor"}); err != nil {
		t.Fatalf("listed scheme refused: %v", err)
	}
}
