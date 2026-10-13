package mcpresource

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteDenial(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteDenial(rec, http.StatusForbidden, Denial{
		Error:            "insufficient_scope",
		ErrorDescription: "need admin",
		RequiredScopes:   []string{"admin"},
		ResourceMetadata: "https://mcp.example.com/.well-known/oauth-protected-resource",
		StepUp:           &StepUpHint{ACRValues: []string{"mfa"}, MaxAge: 60},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("cache-control %q", cc)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"error", "error_description", "required_scopes", "resource_metadata", "step_up"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing field %q in %s", k, rec.Body.String())
		}
	}
}

func TestWriteDenialOmitsEmptyFields(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteDenial(rec, http.StatusUnauthorized, Denial{Error: "invalid_token"})
	if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"invalid_token"}` {
		t.Fatalf("body %s", got)
	}
}

// The existing 401 path keeps its status and header and gains the structured
// body fields.
func TestExistingDenyPathBodyIsStructured(t *testing.T) {
	v := New(testResource, WithJWKS("http://127.0.0.1:1"))
	rec := runMiddleware(v, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	if www := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(www, `Bearer error="invalid_token"`) {
		t.Fatalf("www %q", www)
	}
	var d Denial
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Error != "invalid_token" || d.ResourceMetadata == "" {
		t.Fatalf("body %+v", d)
	}
}
