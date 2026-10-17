package sqlite_test

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/go-chi/chi/v5"
)

// TestOAuthMetadataUnderPathPrefix pins discovery when the host mounts the library under a path
// prefix (http.StripPrefix). RFC 8414 and RFC 9728 documents live at the origin root, so they only
// resolve when the host also forwards that root.
func TestOAuthMetadataUnderPathPrefix(t *testing.T) {
	const (
		prefix   = "/api/v1/auth-lib"
		issuer   = "https://app.example.test" + prefix
		resource = "https://app.example.test/api/mcp"
	)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       newStore(t),
		BaseURL:       "https://app.example.test",
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:    issuer,
			Resources: []theauth.ProtectedResource{{Identifier: resource, Scopes: []string{"files.read"}}},
		},
	})
	if err != nil {
		t.Fatalf("theauth.New: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	lib := chi.NewRouter()
	a.Mount(lib)

	get := func(h http.Handler, path string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		body, _ := io.ReadAll(rec.Body)
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		return rec.Code, doc
	}

	// Host without root forwarding: only the prefix is mounted.
	prefixOnly := http.NewServeMux()
	prefixOnly.Handle(prefix+"/", http.StripPrefix(prefix, lib))

	// Host that also forwards the origin root well-known paths.
	withRoot := http.NewServeMux()
	withRoot.Handle(prefix+"/", http.StripPrefix(prefix, lib))
	withRoot.Handle("/.well-known/", lib)

	t.Run("EndpointsLiveUnderThePrefix", func(t *testing.T) {
		status, doc := get(prefixOnly, prefix+"/.well-known/oauth-authorization-server")
		if status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
		if doc["issuer"] != issuer {
			t.Fatalf("issuer = %v", doc["issuer"])
		}
		for _, k := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
			s, _ := doc[k].(string)
			if !strings.HasPrefix(s, issuer+"/oauth/") {
				t.Errorf("%s = %q, want under %s/oauth/", k, s, issuer)
			}
		}
		if status, _ := get(prefixOnly, prefix+"/oauth/jwks"); status != http.StatusOK {
			t.Fatalf("jwks under prefix: %d", status)
		}
	})

	t.Run("RFC8414OriginRootNeedsHostForwarding", func(t *testing.T) {
		path := "/.well-known/oauth-authorization-server" + prefix
		if status, _ := get(prefixOnly, path); status != http.StatusNotFound {
			t.Fatalf("prefix-only host: %d, want 404 (nothing serves the origin root)", status)
		}
		status, doc := get(withRoot, path)
		if status != http.StatusOK || doc["issuer"] != issuer {
			t.Fatalf("forwarding host: %d %v, want 200 with issuer %s", status, doc, issuer)
		}
		if status, _ := get(withRoot, "/.well-known/openid-configuration"+prefix); status != http.StatusOK {
			t.Fatalf("openid-configuration path form: %d", status)
		}
		if status, _ := get(withRoot, "/.well-known/oauth-authorization-server/other"); status != http.StatusNotFound {
			t.Fatalf("other issuer path: %d, want 404", status)
		}
	})

	t.Run("RFC9728ResourceMetadata", func(t *testing.T) {
		path := "/.well-known/oauth-protected-resource/api/mcp"
		if status, _ := get(prefixOnly, path); status != http.StatusNotFound {
			t.Fatalf("prefix-only host: %d, want 404", status)
		}
		status, doc := get(withRoot, path)
		if status != http.StatusOK || doc["resource"] != resource {
			t.Fatalf("forwarding host: %d %v", status, doc)
		}
	})
}
