package theauth_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

func (e *tokenEnv) rawDo(method, path string, cookie *http.Cookie, bearer string) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestTokenCurrentDescribe(t *testing.T) {
	e := newTokenEnv(t, nil)
	u := e.addUser("u", "read", "deploy")
	raw, id := e.mint("u", "read")

	code, body := e.rawDo("GET", "/auth/tokens/current", nil, raw)
	if code != 200 {
		t.Fatalf("status %d %s", code, body)
	}
	if strings.Contains(body, raw) || strings.Contains(strings.ToLower(body), "hash") || strings.Contains(body, "secret") || strings.Contains(body, "hint") {
		t.Fatalf("response leaks secret material: %s", body)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(body), &out)
	if out["id"] != id || out["ownerId"] != u.ID.String() || out["ownerKind"] != theauth.OwnerKindUser || out["kind"] != theauth.APITokenKindPersonal || out["name"] != "t" {
		t.Fatalf("metadata mismatch: %v", out)
	}
	if ab, _ := out["abilities"].([]any); len(ab) != 1 || ab[0] != "read" {
		t.Fatalf("abilities: %v", out["abilities"])
	}
	for _, k := range []string{"createdAt", "expiresAt", "lastUsedAt"} {
		if out[k] == nil {
			t.Fatalf("missing %s: %v", k, out)
		}
	}

	t.Run("abilities are clamped to the owner's current grant", func(t *testing.T) {
		raw2, _ := e.mint("u", "read", "deploy")
		e.setAbilities(u, []string{"read"})
		_, body := e.rawDo("GET", "/auth/tokens/current", nil, raw2)
		var o map[string]any
		_ = json.Unmarshal([]byte(body), &o)
		if ab, _ := o["abilities"].([]any); len(ab) != 1 || ab[0] != "read" {
			t.Fatalf("abilities not clamped: %v", o["abilities"])
		}
	})

	t.Run("agent token reports kind and agent name", func(t *testing.T) {
		raw3, _, err := e.a.MintAPIToken(context.Background(), theauth.MintAPITokenInput{
			OwnerID: u.ID, OwnerKind: theauth.OwnerKindUser, Name: "ag", Abilities: []string{"read"},
			Kind: theauth.APITokenKindAgent, AgentName: "claude",
		})
		if err != nil {
			t.Fatal(err)
		}
		_, body := e.rawDo("GET", "/auth/tokens/current", nil, raw3)
		var o map[string]any
		_ = json.Unmarshal([]byte(body), &o)
		if o["kind"] != theauth.APITokenKindAgent || o["agentName"] != "claude" {
			t.Fatalf("agent metadata: %v", o)
		}
	})
}

func TestTokenCurrentMinimalAbilitySet(t *testing.T) {
	e := newTokenEnv(t, nil)
	e.addUser("u", "read")
	raw, _ := e.mint("u", "read")
	if code, _ := e.rawDo("GET", "/auth/tokens/current", nil, raw); code != 200 {
		t.Fatalf("minimal token cannot self-describe: %d", code)
	}
	if code, _ := e.rawDo("GET", "/deploy", nil, raw); code != 403 {
		t.Fatalf("self-management must not widen abilities, /deploy gave %d", code)
	}
}

func TestTokenCurrentTouchesOnlyOwnRecord(t *testing.T) {
	e := newTokenEnv(t, nil)
	e.addUser("u", "read", "deploy")
	e.addUser("v", "read")
	rawA, idA := e.mint("u", "read")
	rawB, idB := e.mint("u", "read")
	rawV, idV := e.mint("v", "read")

	tests := []struct {
		name, method, path string
		want               int
	}{
		{"list is session only", "GET", "/auth/tokens", 401},
		{"mint is session only", "POST", "/auth/tokens", 401},
		{"revoke sibling by id is session only", "DELETE", "/auth/tokens/" + idB, 401},
		{"revoke foreign by id is session only", "DELETE", "/auth/tokens/" + idV, 401},
		{"revoke own by id is session only", "DELETE", "/auth/tokens/" + idA, 401},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := e.rawDo(tc.method, tc.path, nil, rawA); code != tc.want {
				t.Fatalf("%s %s = %d, want %d", tc.method, tc.path, code, tc.want)
			}
		})
	}
	if _, err := e.a.AuthenticateAPIToken(context.Background(), rawB); err != nil {
		t.Fatalf("sibling token was touched: %v", err)
	}
	if _, err := e.a.AuthenticateAPIToken(context.Background(), rawV); err != nil {
		t.Fatalf("foreign token was touched: %v", err)
	}
	_, body := e.rawDo("GET", "/auth/tokens/current", nil, rawA)
	if !strings.Contains(body, idA) || strings.Contains(body, idB) || strings.Contains(body, idV) {
		t.Fatalf("current returned another record: %s", body)
	}

	t.Run("current accepts no id and ignores query tricks", func(t *testing.T) {
		_, body := e.rawDo("GET", "/auth/tokens/current?id="+idV+"&owner_id="+idV, nil, rawA)
		if !strings.Contains(body, idA) || strings.Contains(body, idV) {
			t.Fatalf("query redirected the lookup: %s", body)
		}
		if code, _ := e.rawDo("DELETE", "/auth/tokens/current?id="+idV, nil, rawA); code != 204 {
			t.Fatalf("delete current = %d", code)
		}
		if _, err := e.a.AuthenticateAPIToken(context.Background(), rawV); err != nil {
			t.Fatalf("query param revoked a foreign token: %v", err)
		}
	})
	if code, _ := e.rawDo("GET", "/auth/tokens", e.cookies["u"], ""); code != 200 {
		t.Fatalf("session list regressed: %d", code)
	}
}

func TestTokenCurrentSessionIsRejected(t *testing.T) {
	e := newTokenEnv(t, nil)
	e.addUser("u", "read")
	for _, m := range []string{"GET", "DELETE"} {
		code, body := e.rawDo(m, "/auth/tokens/current", e.cookies["u"], "")
		if code != http.StatusForbidden || !strings.Contains(body, "bearer_required") {
			t.Fatalf("%s with session = %d %s", m, code, body)
		}
	}
	if code, _ := e.rawDo("GET", "/auth/tokens/current", nil, ""); code != 401 {
		t.Fatalf("anonymous = %d", code)
	}
	raw, _ := e.mint("u", "read")
	if code, _ := e.rawDo("GET", "/auth/tokens/current", e.cookies["u"], raw); code != 200 {
		t.Fatalf("bearer must win over a cookie: %d", code)
	}
	if code, _ := e.rawDo("GET", "/auth/tokens/current", e.cookies["u"], "tk_bogus"); code != 401 {
		t.Fatalf("bad bearer must not fall back to the cookie: %d", code)
	}
}

func TestTokenCurrentDeadTokensGet401(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		kill func(e *tokenEnv, u theauth.User, id string)
	}{
		{"revoked", func(e *tokenEnv, _ theauth.User, id string) {
			e.rawDo("DELETE", "/auth/tokens/"+id, e.cookies["u"], "")
		}},
		{"expired", func(e *tokenEnv, _ theauth.User, _ string) { e.advance(1000 * 24 * time.Hour) }},
		{"owner disabled", func(e *tokenEnv, u theauth.User, _ string) { e.disable(u.ID) }},
		{"owner tokens revoked", func(e *tokenEnv, u theauth.User, _ string) { _, _ = e.a.RevokeOwnerAPITokens(ctx, u.ID) }},
	}
	for _, tc := range tests {
		for _, m := range []string{"GET", "DELETE"} {
			t.Run(tc.name+" "+m, func(t *testing.T) {
				e := newTokenEnv(t, nil)
				u := e.addUser("u", "read")
				raw, id := e.mint("u", "read")
				tc.kill(e, u, id)
				if code, _ := e.rawDo(m, "/auth/tokens/current", nil, raw); code != 401 {
					t.Fatalf("status %d, want 401", code)
				}
			})
		}
	}
	t.Run("owner row deleted", func(t *testing.T) {
		e := newTokenEnv(t, nil)
		raw, _, _ := e.a.MintAPIToken(ctx, theauth.MintAPITokenInput{OwnerID: ulid.New(), OwnerKind: theauth.OwnerKindUser, Name: "n", Abilities: []string{"read"}})
		if code, _ := e.rawDo("GET", "/auth/tokens/current", nil, raw); code != 401 {
			t.Fatalf("status %d, want 401", code)
		}
	})
}

func TestTokenCurrentRevokeEmitsAuditAndBusEvent(t *testing.T) {
	var mu sync.Mutex
	var events []theauth.AuthEvent
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
		APITokens: &theauth.APITokensConfig{
			UserAbilities: func(context.Context, *theauth.User) ([]string, error) { return []string{"read"}, nil },
		},
		AuthEventSink: func(_ context.Context, ev theauth.AuthEvent) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, ev)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	var bus []theauth.RevocationEvent
	unsub, _ := a.SubscribeRevocations(func(ev theauth.RevocationEvent) {
		mu.Lock()
		defer mu.Unlock()
		bus = append(bus, ev)
	})
	defer unsub()
	u, _ := store.CreateUser(context.Background(), theauth.User{ID: ulid.New(), Email: "a@x.test", Name: "a", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	raw, tok, err := a.MintAPIToken(context.Background(), theauth.MintAPITokenInput{OwnerID: u.ID, OwnerKind: theauth.OwnerKindUser, Name: "n", Abilities: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	call := func() int {
		req, _ := http.NewRequest("DELETE", srv.URL+"/auth/tokens/current", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if c := call(); c != 204 {
		t.Fatalf("first revoke = %d", c)
	}
	if c := call(); c != 401 {
		t.Fatalf("second use of revoked token = %d, want 401", c)
	}
	mu.Lock()
	defer mu.Unlock()
	foundAudit := false
	for _, ev := range events {
		if ev.Type == theauth.AuthEventTokenRevoked && ev.UserID == u.ID.String() {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Fatalf("token.revoked audit not emitted: %+v", events)
	}
	if len(bus) != 1 || bus[0].Kind != theauth.RevocationAPIToken || bus[0].ID != tok.ID.String() {
		t.Fatalf("bus events = %+v", bus)
	}
}

func TestTokenCurrentRateLimited(t *testing.T) {
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		RateLimitPerIP: 3, RateLimitPerEmail: 1000,
		APITokens: &theauth.APITokensConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	defer srv.Close()
	var last int
	for range 6 {
		req, _ := http.NewRequest("GET", srv.URL+"/auth/tokens/current", nil)
		req.Header.Set("Authorization", "Bearer tk_bogus")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("last status %d, want 429", last)
	}
}
