package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/saml/handlers"
	"github.com/go-chi/chi/v5"
)

func TestHandleACS_RelayStateValidation(t *testing.T) {
	tests := []struct {
		name  string
		relay string
		want  string
	}{
		{"same-site path kept", "/app/settings?tab=1", "/app/settings?tab=1"},
		{"allow-listed absolute url kept", "https://app.example.com/home", "https://app.example.com/home"},
		{"allow-listed prefix kept", "https://app.example.com/deep/x", "https://app.example.com/deep/x"},
		{"foreign absolute url falls back", "https://evil.example.net/phish", "/dashboard"},
		{"protocol-relative falls back", "//evil.example.net/phish", "/dashboard"},
		{"backslash trick falls back", "/\\evil.example.net", "/dashboard"},
		{"javascript scheme falls back", "javascript:alert(1)", "/dashboard"},
		{"empty falls back", "", "/dashboard"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := handlers.New(&stubService{finishToken: "tok"}, handlers.SessionCookieConfig{Name: "s", TTL: time.Hour}, "/dashboard")
			h.SetAllowedRelayStates([]string{"https://app.example.com/home", "https://app.example.com/deep/*"})
			r := chi.NewRouter()
			h.Mount(r)
			srv := httptest.NewServer(r)
			defer srv.Close()
			resp := postACS(t, srv, validConnID(), "dGVzdA==", tc.relay)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			if got := resp.Header.Get("Location"); got != tc.want {
				t.Fatalf("Location = %q, want %q", got, tc.want)
			}
		})
	}
}
