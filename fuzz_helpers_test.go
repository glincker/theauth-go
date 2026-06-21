package theauth_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

// stubProvider is a no-network OAuth provider used by fuzz targets that
// need a registered {name} route without actually exchanging codes.
type stubProvider struct{ name string }

func (s *stubProvider) Name() string { return s.name }

func (s *stubProvider) AuthURL(state, codeChallenge, redirectURI string, scopes []string) string {
	return "https://example.invalid/authorize?state=" + state
}

func (s *stubProvider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*theauth.ProviderToken, error) {
	return &theauth.ProviderToken{AccessToken: "stub"}, nil
}

func (s *stubProvider) UserInfo(ctx context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	return &theauth.ProviderUser{ID: "stub-id", Email: "stub@example.invalid"}, nil
}

// newOAuthFuzzAuth returns a TheAuth with one stub provider registered
// plus a chi router that has the standard /auth routes mounted on it.
func newOAuthFuzzAuth(t testing.TB) (*theauth.TheAuth, http.Handler) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("read key: %v", err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:           memory.New(),
		BaseURL:           "http://localhost",
		EncryptionKey:     key,
		PostLoginRedirect: "/",
		Providers:         []theauth.Provider{&stubProvider{name: "stub"}},
	})
	if err != nil {
		t.Fatalf("new theauth: %v", err)
	}
	t.Cleanup(a.Close)
	r := chi.NewRouter()
	a.Mount(r)
	return a, r
}
