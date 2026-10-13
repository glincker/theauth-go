package mcpresource

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func principalFor(t *testing.T, f *fakeAS, claims map[string]any) *Principal {
	t.Helper()
	v := newValidatorAgainst(f)
	base := map[string]any{
		"iss": testResource, "sub": "u", "aud": testResource,
		"exp": time.Now().Add(time.Hour).Unix(), "jti": "j",
	}
	for k, val := range claims {
		base[k] = val
	}
	var got *Principal
	h := v.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got, _ = v.Principal(r.Context()) }))
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/x", nil)
	req.Header.Set("Authorization", "Bearer "+signToken(t, f.kid, f.priv, base))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got == nil {
		t.Fatal("no principal")
	}
	return got
}

func TestPrincipalAuthorizationDetailsFromToken(t *testing.T) {
	f := newFakeAS(t)
	p := principalFor(t, f, map[string]any{"authorization_details": []map[string]any{
		{"type": "payment_initiation", "actions": []string{"initiate"}, "locations": []string{"https://bank.example/pay"}, "creditorName": "ACME"},
	}})
	d := p.AuthorizationDetails()
	if len(d) != 1 || d[0].Type != "payment_initiation" || d[0].Actions[0] != "initiate" || len(d[0].Raw) == 0 {
		t.Fatalf("details %+v", d)
	}
	// Read-only: mutating the returned slice must not change the principal.
	d[0].Type = "tampered"
	d[0].Actions[0] = "tampered"
	if again := p.AuthorizationDetails(); again[0].Type != "payment_initiation" || again[0].Actions[0] != "initiate" {
		t.Fatalf("principal mutated: %+v", again)
	}
}

func TestPrincipalAuthorizationDetailsAbsent(t *testing.T) {
	f := newFakeAS(t)
	if d := principalFor(t, f, nil).AuthorizationDetails(); len(d) != 0 {
		t.Fatalf("details %+v", d)
	}
}

func TestMalformedAuthorizationDetailsRejected(t *testing.T) {
	f := newFakeAS(t)
	v := newValidatorAgainst(f)
	tok := signToken(t, f.kid, f.priv, map[string]any{
		"iss": testResource, "sub": "u", "aud": testResource, "exp": time.Now().Add(time.Hour).Unix(), "jti": "j",
		"authorization_details": []map[string]any{{"actions": []string{"x"}}},
	})
	rec := runMiddleware(v, "Bearer "+tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestPrincipalAuthorizationDetailsFromIntrospection(t *testing.T) {
	f := newFakeAS(t)
	intro := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"active":true,"authorization_details":[{"type":"file_access","identifier":"f-1","privileges":["read"]}]}`))
	}))
	defer intro.Close()
	v := New(testResource, WithJWKS(f.jwksServer.URL), WithIntrospection(intro.URL, "c", "s"))
	tok := signToken(t, f.kid, f.priv, map[string]any{
		"iss": testResource, "sub": "u", "aud": testResource, "exp": time.Now().Add(time.Hour).Unix(),
		"jti": "j", "delegation_grant_id": "g-1",
	})
	var got *Principal
	h := v.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got, _ = v.Principal(r.Context()) }))
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got == nil {
		t.Fatal("no principal")
	}
	d := got.AuthorizationDetails()
	if len(d) != 1 || d[0].Type != "file_access" || d[0].Identifier != "f-1" || d[0].Privileges[0] != "read" {
		t.Fatalf("details %+v", d)
	}
}
