package bench

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

// BenchmarkSCIMTokenAuth measures the per-request cost of SCIM bearer
// authentication: sha256 hash of the presented token, one in-memory map
// lookup for the matching row, and context injection. The test drives the
// full HTTP middleware stack so the measured cost matches the production
// path.
//
// gate:include
func BenchmarkSCIMTokenAuth(b *testing.B) {
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "http://localhost",
		SecureCookie:  false,
		Organizations: &theauth.OrganizationsConfig{},
		SCIM:          &theauth.SCIMConfig{RequireHTTPS: false},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(a.Close)

	// Create an organization and mint a SCIM token.
	ownerID := ulid.New()
	_, err = store.CreateUser(context.Background(), theauth.User{
		ID:    ownerID,
		Email: "scim-bench-owner@example.com",
	})
	if err != nil {
		b.Fatal(err)
	}
	org, err := a.CreateOrganization(context.Background(), "Bench Org", "bench-org", ownerID)
	if err != nil {
		b.Fatal(err)
	}
	plaintext, _, err := a.CreateSCIMToken(context.Background(), org.ID, "bench-token")
	if err != nil {
		b.Fatal(err)
	}

	r := chi.NewRouter()
	a.Mount(r)

	// Probe via GET /scim/v2/Users to ensure the auth middleware is exercised.
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		req.Header.Set("Authorization", "Bearer "+plaintext)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		// 200 OK or 404 (no users yet) both confirm auth passed.
		if rec.Code == http.StatusUnauthorized {
			b.Fatalf("SCIM auth rejected valid token: %s", rec.Body.String())
		}
	}
}
