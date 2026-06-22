package as_test

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

func TestProtectedResourceMetadata_Default(t *testing.T) {
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://auth.example.com",
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			Resources:       []theauth.ProtectedResource{{Identifier: "https://mcp.example.com", DisplayName: "MCP", Scopes: []string{"read", "write"}}},
			DisableRotation: true,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	mux := chi.NewRouter()
	a.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var doc theauth.ProtectedResourceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Resource != "https://mcp.example.com" {
		t.Errorf("resource=%q, want https://mcp.example.com", doc.Resource)
	}
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != "https://auth.example.com" {
		t.Errorf("authorization_servers=%v", doc.AuthorizationServers)
	}
	if len(doc.BearerMethodsSupported) == 0 || doc.BearerMethodsSupported[0] != "header" {
		t.Errorf("bearer_methods_supported=%v, want [header]", doc.BearerMethodsSupported)
	}
}
