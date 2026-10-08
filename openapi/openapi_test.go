package openapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestGenerate(t *testing.T) {
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	r := chi.NewRouter()
	r.Route("/auth", func(r chi.Router) {
		r.Post("/magic-link", h)
		r.Get("/me", h)
		r.Delete("/sessions/{id}", h)
		r.Get("/custom/thing/", h)
	})
	r.Post("/oauth/token", h)

	raw, err := Generate(r, Info{Title: "T", Version: "1", ServerURL: "https://a.example"})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenAPI string                               `json:"openapi"`
		Servers []map[string]string                  `json:"servers"`
		Paths   map[string]map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.1.0" || len(doc.Servers) != 1 {
		t.Fatalf("header: %+v", doc)
	}
	tests := []struct {
		path, method string
		summary      string
		secured      bool
		hasBody      bool
		hasParam     bool
	}{
		{"/auth/magic-link", "post", "Request a magic link", false, true, false},
		{"/auth/me", "get", "Return the signed-in user", true, false, false},
		{"/auth/sessions/{id}", "delete", "Revoke one session", true, false, true},
		{"/auth/custom/thing", "get", "GET /auth/custom/thing", false, false, false},
		{"/oauth/token", "post", "OAuth token endpoint", false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			item, ok := doc.Paths[tc.path][tc.method]
			if !ok {
				t.Fatalf("missing operation; paths=%v", doc.Paths)
			}
			if item["summary"] != tc.summary {
				t.Fatalf("summary %v", item["summary"])
			}
			if _, got := item["security"]; got != tc.secured {
				t.Fatalf("security present=%v want %v", got, tc.secured)
			}
			if _, got := item["requestBody"]; got != tc.hasBody {
				t.Fatalf("requestBody present=%v want %v", got, tc.hasBody)
			}
			if _, got := item["parameters"]; got != tc.hasParam {
				t.Fatalf("parameters present=%v want %v", got, tc.hasParam)
			}
		})
	}
}

func TestOperationID(t *testing.T) {
	tests := map[string]string{
		"/auth/sessions/{id}": "delete_auth_sessions_id",
	}
	for route, want := range tests {
		if got := operationID("DELETE", route); got != want {
			t.Errorf("operationID(%q) = %q want %q", route, got, want)
		}
	}
}
