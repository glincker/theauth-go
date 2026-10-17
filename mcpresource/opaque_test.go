package mcpresource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const opaqueResource = "https://mcp.example.com/mcp"

// opaqueAS is a fake RFC 7662 endpoint keyed by raw token.
type opaqueAS struct {
	srv     *httptest.Server
	calls   atomic.Int64
	mu      sync.Mutex
	answers map[string]map[string]any
	maxAge  string // Cache-Control value, "" for none
	seen    []string
}

func newOpaqueAS(t *testing.T) *opaqueAS {
	t.Helper()
	a := &opaqueAS{answers: map[string]map[string]any{}}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.calls.Add(1)
		if u, p, ok := r.BasicAuth(); !ok || u != "rs" || p != "rs-secret" {
			http.Error(w, "bad client", http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		tok := r.PostFormValue("token")
		a.mu.Lock()
		ans, ok := a.answers[tok]
		cc := a.maxAge
		a.seen = append(a.seen, tok)
		a.mu.Unlock()
		if !ok {
			ans = map[string]any{"active": false}
		}
		if cc != "" {
			w.Header().Set("Cache-Control", cc)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ans)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *opaqueAS) set(tok string, ans map[string]any) {
	a.mu.Lock()
	a.answers[tok] = ans
	a.mu.Unlock()
}

func (a *opaqueAS) setMaxAge(v string) {
	a.mu.Lock()
	a.maxAge = v
	a.mu.Unlock()
}

func activeAnswer(over map[string]any) map[string]any {
	m := map[string]any{
		"active":     true,
		"scope":      "files.read files.write",
		"client_id":  "client-1",
		"token_type": "Bearer",
		"sub":        "user-1",
		"aud":        opaqueResource,
		"iss":        "https://as.example.com",
		"jti":        "jti-1",
		"iat":        time.Now().Add(-time.Minute).Unix(),
		"exp":        time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range over {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

func newOpaqueValidator(a *opaqueAS, opts ...Option) *Validator {
	base := []Option{WithIntrospection(a.srv.URL, "rs", "rs-secret"), WithOpaqueTokens()}
	return New(opaqueResource, append(base, opts...)...)
}

func serve(v *Validator, scheme, token string, hdr map[string]string) *httptest.ResponseRecorder {
	var got *Principal
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = v.Principal(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/mcp", nil)
	req.Header.Set("Authorization", scheme+" "+token)
	for k, val := range hdr {
		req.Header.Set(k, val)
	}
	h.ServeHTTP(rec, req)
	if got != nil {
		rec.Header().Set("X-Test-Sub", got.Subject)
	}
	return rec
}

func principalOf(t *testing.T, v *Validator, token string) *Principal {
	t.Helper()
	var got *Principal
	h := v.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = v.Principal(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || got == nil {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	return got
}

func TestOpaquePrincipal(t *testing.T) {
	a := newOpaqueAS(t)
	v := newOpaqueValidator(a)
	exp := time.Now().Add(time.Hour).Unix()
	a.set("opaque-token-full", activeAnswer(map[string]any{
		"exp":                 exp,
		"act":                 map[string]any{"sub": "agent:outer", "act": map[string]any{"sub": "agent:inner"}},
		"delegation_grant_id": "grant-9",
		"device_id":           "dev-3",
		"acr":                 "urn:mfa",
		"amr":                 []string{"pwd", "otp"},
		"auth_time":           int64(1700000000),
		"aud":                 []string{"https://other.example.com", opaqueResource},
		"authorization_details": []map[string]any{
			{"type": "payment"},
		},
	}))
	p := principalOf(t, v, "opaque-token-full")
	if p.Subject != "user-1" || p.ClientID != "client-1" || p.Issuer != "https://as.example.com" || p.JWTID != "jti-1" {
		t.Fatalf("identity fields: %+v", p)
	}
	if p.Audience != opaqueResource || len(p.Audiences) != 2 {
		t.Fatalf("audience: %q %v", p.Audience, p.Audiences)
	}
	if strings.Join(p.Scope, ",") != "files.read,files.write" {
		t.Fatalf("scope: %v", p.Scope)
	}
	if p.ExpiresAt.Unix() != exp || p.IssuedAt.IsZero() {
		t.Fatalf("times: %v %v", p.ExpiresAt, p.IssuedAt)
	}
	if p.Actor != "agent:inner" || strings.Join(p.ActorChain, ",") != "agent:inner,agent:outer" {
		t.Fatalf("actor: %q %v", p.Actor, p.ActorChain)
	}
	if p.DelegationGrantID != "grant-9" || p.DeviceID != "dev-3" || p.ACR != "urn:mfa" || len(p.AMR) != 2 || p.AuthTime.Unix() != 1700000000 {
		t.Fatalf("extras: %+v", p)
	}
	if len(p.AuthorizationDetails()) != 1 {
		t.Fatalf("authorization_details: %v", p.AuthorizationDetails())
	}
}

func TestOpaqueRejections(t *testing.T) {
	tests := []struct {
		name   string
		answer map[string]any
		want   int
	}{
		{"active", activeAnswer(nil), http.StatusOK},
		{"empty scope allowed", activeAnswer(map[string]any{"scope": nil}), http.StatusOK},
		{"no token_type allowed", activeAnswer(map[string]any{"token_type": nil}), http.StatusOK},
		{"inactive", map[string]any{"active": false}, http.StatusUnauthorized},
		{"wrong audience", activeAnswer(map[string]any{"aud": "https://other.example.com"}), http.StatusUnauthorized},
		{"missing aud", activeAnswer(map[string]any{"aud": nil}), http.StatusUnauthorized},
		{"expired", activeAnswer(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}), http.StatusUnauthorized},
		{"missing exp", activeAnswer(map[string]any{"exp": nil}), http.StatusUnauthorized},
		{"iat in the future", activeAnswer(map[string]any{"iat": time.Now().Add(time.Hour).Unix()}), http.StatusUnauthorized},
		{"refresh token", activeAnswer(map[string]any{"token_type": "refresh_token"}), http.StatusUnauthorized},
		{"dpop without cnf", activeAnswer(map[string]any{"token_type": "DPoP"}), http.StatusUnauthorized},
		{"cnf without dpop verifier", activeAnswer(map[string]any{"cnf": map[string]any{"jkt": "abc"}}), http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newOpaqueAS(t)
			v := newOpaqueValidator(a)
			a.set("opaque-token-1", tc.answer)
			rec := serve(v, "Bearer", "opaque-token-1", nil)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d, body %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusUnauthorized {
				wa := rec.Header().Get("WWW-Authenticate")
				if !strings.Contains(wa, `error="invalid_token"`) ||
					!strings.Contains(wa, `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`) {
					t.Fatalf("WWW-Authenticate = %q", wa)
				}
			}
		})
	}
}

func TestOpaqueCache(t *testing.T) {
	tests := []struct {
		name       string
		cc         string
		ttl        time.Duration
		advance    time.Duration
		wantCalls  int64
		wantStatus int
	}{
		{"hit inside default ttl", "", 0, 30 * time.Second, 1, http.StatusOK},
		{"default ttl lapses", "", 0, 61 * time.Second, 2, http.StatusOK},
		{"WithCacheTTL honored", "", 5 * time.Second, 6 * time.Second, 2, http.StatusOK},
		{"WithCacheTTL zero ignored", "", -1, 30 * time.Second, 1, http.StatusOK},
		{"short max-age expires", "private, max-age=2", 0, 3 * time.Second, 2, http.StatusOK},
		{"short max-age hit", "private, max-age=2", 0, time.Second, 1, http.StatusOK},
		{"long max-age beats ttl", "private, max-age=600", 5 * time.Second, 300 * time.Second, 1, http.StatusOK},
		{"max-age 0 falls back to ttl", "private, max-age=0", 0, 30 * time.Second, 1, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newOpaqueAS(t)
			a.setMaxAge(tc.cc)
			var opts []Option
			if tc.ttl != 0 {
				opts = append(opts, WithCacheTTL(tc.ttl))
			}
			v := newOpaqueValidator(a, opts...)
			now := time.Now()
			v.introspect.now = func() time.Time { return now }
			a.set("opaque-token-1", activeAnswer(nil))
			if rec := serve(v, "Bearer", "opaque-token-1", nil); rec.Code != http.StatusOK {
				t.Fatalf("first: %d", rec.Code)
			}
			now = now.Add(tc.advance)
			if rec := serve(v, "Bearer", "opaque-token-1", nil); rec.Code != tc.wantStatus {
				t.Fatalf("second: %d", rec.Code)
			}
			if got := a.calls.Load(); got != tc.wantCalls {
				t.Fatalf("introspection calls = %d, want %d", got, tc.wantCalls)
			}
		})
	}
}

func TestOpaqueRevocationAfterCacheWindow(t *testing.T) {
	a := newOpaqueAS(t)
	a.setMaxAge("private, max-age=5")
	v := newOpaqueValidator(a)
	now := time.Now()
	v.introspect.now = func() time.Time { return now }
	a.set("opaque-token-1", activeAnswer(nil))
	if rec := serve(v, "Bearer", "opaque-token-1", nil); rec.Code != http.StatusOK {
		t.Fatalf("before revoke: %d", rec.Code)
	}
	a.set("opaque-token-1", map[string]any{"active": false}) // revoked at the AS
	now = now.Add(2 * time.Second)
	if rec := serve(v, "Bearer", "opaque-token-1", nil); rec.Code != http.StatusOK {
		t.Fatalf("inside the cache window the cached answer is served: %d", rec.Code)
	}
	now = now.Add(4 * time.Second)
	if rec := serve(v, "Bearer", "opaque-token-1", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after the window: %d, want 401", rec.Code)
	}
}

func TestOpaqueNoIntrospectionFailsClosed(t *testing.T) {
	v := New(opaqueResource, WithOpaqueTokens())
	var found bool
	for _, d := range v.Diagnostics() {
		if d.Code == "opaque-no-introspection" && d.Severity == "warn" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Diagnostics = %+v, want opaque-no-introspection", v.Diagnostics())
	}
	// With a JWKS but no introspection, opaque tokens are refused.
	f := newFakeAS(t)
	v = New(opaqueResource, WithJWKS(f.jwksServer.URL), WithOpaqueTokens())
	if rec := serve(v, "Bearer", "opaque-token-1", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if got := f.introspectCalls.Load(); got != 0 {
		t.Fatalf("introspection called %d times", got)
	}
}

func TestOpaqueDiagnosticsWithIntrospection(t *testing.T) {
	a := newOpaqueAS(t)
	for _, d := range newOpaqueValidator(a).Diagnostics() {
		if d.Code == "opaque-no-introspection" {
			t.Fatalf("unexpected diagnostic %+v", d)
		}
	}
}

func TestOpaqueNotEnabledDoesNotIntrospect(t *testing.T) {
	a := newOpaqueAS(t)
	f := newFakeAS(t)
	a.set("opaque-token-1", activeAnswer(nil))
	v := New(opaqueResource, WithJWKS(f.jwksServer.URL), WithIntrospection(a.srv.URL, "rs", "rs-secret"))
	if rec := serve(v, "Bearer", "opaque-token-1", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if got := a.calls.Load(); got != 0 {
		t.Fatalf("introspection called %d times without WithOpaqueTokens", got)
	}
}

func TestOpaqueMalformedNeverReachesAS(t *testing.T) {
	a := newOpaqueAS(t)
	v := newOpaqueValidator(a)
	tests := []struct{ name, token string }{
		{"spaces", "has space"},
		{"control", "bad\x01token"},
		{"quote", `a"b`},
		{"too long", strings.Repeat("a", maxOpaqueTokenLen+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/mcp", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			if _, err := v.authenticate(req, tc.token, "Bearer"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if got := a.calls.Load(); got != 0 {
		t.Fatalf("AS called %d times for malformed tokens", got)
	}
}

func TestOpaqueJWTPathUnchanged(t *testing.T) {
	f := newFakeAS(t)
	a := newOpaqueAS(t)
	v := New(testResource, WithJWKS(f.jwksServer.URL), WithIntrospection(a.srv.URL, "rs", "rs-secret"), WithOpaqueTokens())
	good := signToken(t, f.kid, f.priv, map[string]any{
		"sub": "user-1", "aud": testResource, "exp": time.Now().Add(time.Hour).Unix(), "scope": "read",
	})
	if rec := serve(v, "Bearer", good, nil); rec.Code != http.StatusOK {
		t.Fatalf("valid JWT: %d", rec.Code)
	}
	// An invalid JWT shaped token must not fall back to introspection even
	// when the AS would call it active.
	bad := good[:len(good)-4] + "AAAA"
	a.set(bad, activeAnswer(nil))
	if rec := serve(v, "Bearer", bad, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("tampered JWT: %d", rec.Code)
	}
	if got := a.calls.Load(); got != 0 {
		t.Fatalf("introspection called %d times for JWT shaped tokens", got)
	}
}

func TestLooksLikeJWT(t *testing.T) {
	tests := []struct {
		token string
		want  bool
	}{
		{"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", true},
		{"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0.", false},
		{"eyJhbGciOiJFUzI1NiJ9..c2ln", false},
		{"eyJhbGciOiJFUzI1NiJ9.eyJ.c2ln.extra", false},
		{"eyJhbGciOiJFUzI1NiJ9.eyJ", false},
		{"abc.def.ghi", false},
		{"eyJ+/.a.b", false},
		{"opaque-token", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := looksLikeJWT(tc.token); got != tc.want {
			t.Errorf("looksLikeJWT(%q) = %v, want %v", tc.token, got, tc.want)
		}
	}
	if n := testing.AllocsPerRun(100, func() { looksLikeJWT("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln") }); n != 0 {
		t.Errorf("looksLikeJWT allocates %v", n)
	}
}

func TestOpaqueConcurrent(t *testing.T) {
	a := newOpaqueAS(t)
	v := newOpaqueValidator(a)
	for i := 0; i < 8; i++ {
		a.set(fmt.Sprintf("opaque-token-%d", i), activeAnswer(nil))
	}
	var wg sync.WaitGroup
	var bad atomic.Int64
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				tok := fmt.Sprintf("opaque-token-%d", (g+i)%9) // index 8 is unknown
				rec := serve(v, "Bearer", tok, nil)
				want := http.StatusOK
				if strings.HasSuffix(tok, "-8") {
					want = http.StatusUnauthorized
				}
				if rec.Code != want {
					bad.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d wrong answers", bad.Load())
	}
}

func TestOpaqueCacheKeyNeverHoldsToken(t *testing.T) {
	a := newOpaqueAS(t)
	v := newOpaqueValidator(a)
	const tok = "super-secret-opaque-token"
	a.set(tok, activeAnswer(nil))
	if rec := serve(v, "Bearer", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	sum := sha256.Sum256([]byte(tok))
	wantKey := hex.EncodeToString(sum[:]) + ":" + opaqueResource
	v.introspect.mu.RLock()
	defer v.introspect.mu.RUnlock()
	if len(v.introspect.entries) != 1 {
		t.Fatalf("entries = %d", len(v.introspect.entries))
	}
	for k := range v.introspect.entries {
		if strings.Contains(k, tok) || k != wantKey {
			t.Fatalf("cache key %q", k)
		}
	}
}

func TestOpaqueErrorsDoNotLeakToken(t *testing.T) {
	const tok = "leaky-opaque-token"
	// Unreachable AS: the error text surfaces in the 401 body.
	v := New(opaqueResource, WithIntrospection("http://127.0.0.1:1/introspect", "rs", "x"), WithOpaqueTokens())
	rec := serve(v, "Bearer", tok, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), tok) || strings.Contains(rec.Header().Get("WWW-Authenticate"), tok) {
		t.Fatal("token leaked in the error response")
	}
}

func TestOpaqueCacheBounded(t *testing.T) {
	a := newOpaqueAS(t)
	c := newIntrospectCache(a.srv.URL, "rs", "rs-secret", nil, time.Hour)
	for i := 0; i < maxIntrospectEntries+50; i++ {
		c.mu.Lock()
		c.evictLocked()
		c.entries[fmt.Sprintf("k%d", i)] = &introspectCacheEntry{expiresAt: time.Now().Add(time.Hour)}
		c.mu.Unlock()
	}
	if len(c.entries) > maxIntrospectEntries {
		t.Fatalf("cache grew to %d", len(c.entries))
	}
}

func TestOpaqueDPoP(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const url = "https://mcp.example.com/mcp"
	const tok = "dpop-bound-opaque-token"
	_, thumb := signDPoPProofES256(t, priv, "GET", url, "ignored", time.Now())
	answer := activeAnswer(map[string]any{"token_type": "DPoP", "cnf": map[string]any{"jkt": thumb}})

	t.Run("matching proof", func(t *testing.T) {
		a := newOpaqueAS(t)
		a.set(tok, answer)
		v := newOpaqueValidator(a, WithDPoPVerification(nil, 0, 0))
		proof, _ := signDPoPProofES256(t, priv, "GET", url, tok, time.Now())
		rec := serve(v, "DPoP", tok, map[string]string{"DPoP": proof})
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d %s", rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	})
	t.Run("bearer scheme refused", func(t *testing.T) {
		a := newOpaqueAS(t)
		a.set(tok, answer)
		v := newOpaqueValidator(a, WithDPoPVerification(nil, 0, 0))
		if rec := serve(v, "Bearer", tok, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("foreign key refused", func(t *testing.T) {
		a := newOpaqueAS(t)
		a.set(tok, answer)
		v := newOpaqueValidator(a, WithDPoPVerification(nil, 0, 0))
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		proof, _ := signDPoPProofES256(t, other, "GET", url, tok, time.Now())
		if rec := serve(v, "DPoP", tok, map[string]string{"DPoP": proof}); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("no verifier configured refused", func(t *testing.T) {
		a := newOpaqueAS(t)
		a.set(tok, answer)
		v := newOpaqueValidator(a)
		proof, _ := signDPoPProofES256(t, priv, "GET", url, tok, time.Now())
		if rec := serve(v, "DPoP", tok, map[string]string{"DPoP": proof}); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})
}

func TestOpaqueOnlyNoJWKS(t *testing.T) {
	a := newOpaqueAS(t)
	a.set("opaque-token-1", activeAnswer(nil))
	v := newOpaqueValidator(a)
	if rec := serve(v, "Bearer", "opaque-token-1", nil); rec.Code != http.StatusOK {
		t.Fatalf("opaque only deployment: %d", rec.Code)
	}
	// A JWT shaped token fails closed without a JWKS.
	if rec := serve(v, "Bearer", "eyJhbGciOiJFZERTQSIsImtpZCI6ImsifQ.eyJzdWIiOiIxIn0.c2ln", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("JWT without JWKS: %d", rec.Code)
	}
}
