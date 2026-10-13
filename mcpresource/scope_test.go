package mcpresource

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// guarded builds Middleware(guard(ok handler)) and returns the recorder for a
// request carrying a token minted with the given extra claims.
func guarded(t *testing.T, extra map[string]any, guard func(*Validator) func(http.Handler) http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	f := newFakeAS(t)
	v := newValidatorAgainst(f)
	claims := map[string]any{
		"iss": testResource, "sub": "user-1", "aud": testResource,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"jti": "jti-1", "client_id": "client-1", "scope": "read write",
	}
	for k, val := range extra {
		claims[k] = val
	}
	tok := signToken(t, f.kid, f.priv, claims)
	h := v.Middleware(guard(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/tools", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(rec, req)
	return rec
}

func TestRequireScope(t *testing.T) {
	tests := []struct {
		name       string
		scopes     []string
		wantStatus int
	}{
		{"all present", []string{"read", "write"}, http.StatusOK},
		{"one missing", []string{"read", "admin"}, http.StatusForbidden},
		{"none required", nil, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := guarded(t, nil, func(v *Validator) func(http.Handler) http.Handler { return v.RequireScope(tc.scopes...) })
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d want %d body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestRequireScopeChallenge(t *testing.T) {
	rec := guarded(t, nil, func(v *Validator) func(http.Handler) http.Handler { return v.RequireScope("read", "admin") })
	www := rec.Header().Get("WWW-Authenticate")
	for _, want := range []string{
		`Bearer error="insufficient_scope"`,
		`scope="read admin"`,
		`resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`,
	} {
		if !strings.Contains(www, want) {
			t.Fatalf("WWW-Authenticate %q missing %q", www, want)
		}
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	var body Denial
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body.Error != "insufficient_scope" || strings.Join(body.RequiredScopes, " ") != "read admin" || body.ResourceMetadata == "" {
		t.Fatalf("body %+v", body)
	}
}

func TestRequireScopeWithoutPrincipal(t *testing.T) {
	v := New(testResource, WithJWKS("http://127.0.0.1:1"))
	h := v.RequireScope("read")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://mcp.example.com/x", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestRequireStepUp(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name   string
		claims map[string]any
		policy StepUp
		want   int
	}{
		{"acr satisfied", map[string]any{"acr": "mfa"}, StepUp{ACRValues: []string{"mfa", "hwk"}}, http.StatusOK},
		{"acr missing", nil, StepUp{ACRValues: []string{"mfa"}}, http.StatusUnauthorized},
		{"acr wrong", map[string]any{"acr": "pwd"}, StepUp{ACRValues: []string{"mfa"}}, http.StatusUnauthorized},
		{"fresh auth_time", map[string]any{"auth_time": now.Add(-time.Minute).Unix()}, StepUp{MaxAge: 5 * time.Minute}, http.StatusOK},
		{"stale auth_time", map[string]any{"auth_time": now.Add(-time.Hour).Unix()}, StepUp{MaxAge: 5 * time.Minute}, http.StatusUnauthorized},
		{"missing auth_time", nil, StepUp{MaxAge: 5 * time.Minute}, http.StatusUnauthorized},
		{"both satisfied", map[string]any{"acr": "mfa", "auth_time": now.Unix()}, StepUp{ACRValues: []string{"mfa"}, MaxAge: time.Minute}, http.StatusOK},
		{"empty policy passes", nil, StepUp{}, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := guarded(t, tc.claims, func(v *Validator) func(http.Handler) http.Handler { return v.RequireStepUp(tc.policy) })
			if rec.Code != tc.want {
				t.Fatalf("status %d want %d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestStepUpChallengeShape(t *testing.T) {
	rec := guarded(t, map[string]any{"acr": "pwd"}, func(v *Validator) func(http.Handler) http.Handler {
		return v.RequireStepUp(StepUp{ACRValues: []string{"mfa", "hwk"}, MaxAge: 5 * time.Minute})
	})
	www := rec.Header().Get("WWW-Authenticate")
	for _, want := range []string{
		`Bearer error="insufficient_user_authentication"`,
		`acr_values="mfa hwk"`,
		`max_age="300"`,
		`resource_metadata="`,
	} {
		if !strings.Contains(www, want) {
			t.Fatalf("WWW-Authenticate %q missing %q", www, want)
		}
	}
	var body Denial
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "insufficient_user_authentication" || body.StepUp == nil ||
		strings.Join(body.StepUp.ACRValues, " ") != "mfa hwk" || body.StepUp.MaxAge != 300 {
		t.Fatalf("body %+v", body)
	}
}

func TestPrincipalExposesACRAndAuthTime(t *testing.T) {
	at := time.Now().Add(-time.Minute).Unix()
	f := newFakeAS(t)
	v := newValidatorAgainst(f)
	tok := signToken(t, f.kid, f.priv, map[string]any{
		"iss": testResource, "sub": "u", "aud": testResource, "exp": time.Now().Add(time.Hour).Unix(),
		"jti": "j", "acr": "mfa", "auth_time": at, "amr": []string{"pwd", "otp"},
	})
	var got *Principal
	h := v.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got, _ = v.Principal(r.Context()) }))
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got == nil || got.ACR != "mfa" || got.AuthTime.Unix() != at || len(got.AMR) != 2 {
		t.Fatalf("principal %+v", got)
	}
}
