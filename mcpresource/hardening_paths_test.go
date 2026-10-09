package mcpresource

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProtectedResourceMetadataURL(t *testing.T) {
	tests := []struct {
		resource string
		want     string
	}{
		{"https://mcp.example.com", "https://mcp.example.com/.well-known/oauth-protected-resource"},
		{"https://mcp.example.com/", "https://mcp.example.com/.well-known/oauth-protected-resource"},
		{"https://mcp.example.com/api/mcp", "https://mcp.example.com/.well-known/oauth-protected-resource/api/mcp"},
		{"https://mcp.example.com/mcp?tenant=a", "https://mcp.example.com/.well-known/oauth-protected-resource/mcp?tenant=a"},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.resource, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/x", nil)
			if got := protectedResourceMetadataURL(r, tc.resource); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWithClockSkew(t *testing.T) {
	tests := []struct {
		name    string
		skew    time.Duration
		expired time.Duration
		want    int
	}{
		{"default tolerates 30s expiry", 0, 30 * time.Second, http.StatusOK},
		{"default rejects 5m expiry", 0, 5 * time.Minute, http.StatusUnauthorized},
		{"wide skew accepts 5m expiry", 10 * time.Minute, 5 * time.Minute, http.StatusOK},
		{"tight skew rejects 30s expiry", time.Second, 30 * time.Second, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAS(t)
			opts := []Option{
				WithJWKS(f.jwksServer.URL),
				WithIntrospection(f.introspectServer.URL, "client-1", "secret-1"),
			}
			if tc.skew > 0 {
				opts = append(opts, WithClockSkew(tc.skew))
			}
			v := New(testResource, opts...)
			now := time.Now()
			tok := signToken(t, f.kid, f.priv, map[string]any{
				"iss": testResource, "sub": "u", "aud": testResource,
				"exp": now.Add(-tc.expired).Unix(), "iat": now.Add(-time.Hour).Unix(),
				"jti": "j", "client_id": "client-1", "scope": "read",
			})
			if rec := runMiddleware(v, "Bearer "+tok); rec.Code != tc.want {
				t.Fatalf("status %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestJWKSMalformedKeysAreNotSilentlyEmpty(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"bad x", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"!!!"}]}`, true},
		{"short x", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"AAAA"}]}`, true},
		{"missing kid", `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA"}]}`, true},
		{"empty set", `{"keys":[]}`, true},
		{"not json", `nope`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := newJWKSCache(srv.URL, nil, time.Minute)
			if _, err := c.PublicKey("k"); err == nil {
				t.Fatal("expected error for unusable JWKS")
			}
		})
	}
}
