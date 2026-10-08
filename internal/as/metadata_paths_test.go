package as_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	theauth "github.com/glincker/theauth-go/v2"
)

// RFC 8414 section 3.1 and RFC 9728 section 3.1: the well-known segment is
// inserted between the host and the path of the issuer or resource.
func TestWellKnownPathComponents(t *testing.T) {
	a, _ := newASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		c.Issuer = "https://auth.example.com/tenant1"
	})
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	tests := []struct {
		name string
		path string
		want int
	}{
		{"as plain", "/.well-known/oauth-authorization-server", http.StatusOK},
		{"as issuer path", "/.well-known/oauth-authorization-server/tenant1", http.StatusOK},
		{"as other issuer path", "/.well-known/oauth-authorization-server/other", http.StatusNotFound},
		{"oidc plain", "/.well-known/openid-configuration", http.StatusOK},
		{"oidc issuer path", "/.well-known/openid-configuration/tenant1", http.StatusOK},
		{"oidc other issuer path", "/.well-known/openid-configuration/other", http.StatusNotFound},
		{"resource path on other origin", "/.well-known/oauth-protected-resource/mcp", http.StatusOK},
		{"resource trailing slash", "/.well-known/oauth-protected-resource/mcp/", http.StatusOK},
		{"unknown resource", "/.well-known/oauth-protected-resource/nope", http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.want {
				t.Fatalf("GET %s: status %d, want %d (%s)", tc.path, resp.StatusCode, tc.want, body)
			}
		})
	}
}
