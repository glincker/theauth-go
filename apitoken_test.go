package theauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

type tokenEnv struct {
	t        *testing.T
	a        *theauth.TheAuth
	store    *memory.Store
	srv      *httptest.Server
	abil     map[theauth.ULID][]string
	mu       sync.Mutex
	disabled map[theauth.ULID]bool
	clock    atomic.Int64
	users    map[string]theauth.User
	cookies  map[string]*http.Cookie
}

func (e *tokenEnv) setAbilities(u theauth.User, ab []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.abil[u.ID] = ab
}

func (e *tokenEnv) disable(id theauth.ULID) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disabled[id] = true
}

func newTokenEnv(t *testing.T, mutate func(*theauth.APITokensConfig)) *tokenEnv {
	t.Helper()
	e := &tokenEnv{t: t, store: memory.New(), abil: map[theauth.ULID][]string{}, disabled: map[theauth.ULID]bool{}, users: map[string]theauth.User{}, cookies: map[string]*http.Cookie{}}
	e.clock.Store(time.Now().UnixNano())
	cfg := &theauth.APITokensConfig{
		Prefix: "tk",
		UserAbilities: func(_ context.Context, u *theauth.User) ([]string, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.abil[u.ID], nil
		},
		IsAdmin: func(_ context.Context, u *theauth.User) (bool, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			return len(e.abil[u.ID]) == 1 && e.abil[u.ID][0] == theauth.AbilityRoot, nil
		},
		OwnerActive: func(_ context.Context, id theauth.ULID) (bool, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			return !e.disabled[id], nil
		},
		Device: &theauth.DeviceConfig{Interval: time.Millisecond, DefaultAbilities: []string{"read"}},
	}
	if mutate != nil {
		mutate(cfg)
	}
	a, err := theauth.New(theauth.Config{
		Storage: e.store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000, APITokens: cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	theauth.SetAPITokenClockForTest(a, func() time.Time { return time.Unix(0, e.clock.Load()).UTC() })
	e.a = a
	r := chi.NewRouter()
	a.Mount(r)
	r.With(a.RequireAbility("deploy")).Get("/deploy", func(w http.ResponseWriter, r *http.Request) {
		p, _ := theauth.PrincipalFromContext(r.Context())
		_, _ = w.Write([]byte(string(p.Kind)))
	})
	e.srv = httptest.NewServer(r)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *tokenEnv) addUser(name string, abilities ...string) theauth.User {
	e.t.Helper()
	u, err := e.store.CreateUser(context.Background(), theauth.User{ID: ulid.New(), Email: name + "@x.test", Name: name, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		e.t.Fatal(err)
	}
	e.setAbilities(u, abilities)
	tok, _, err := theauth.IssueSessionForTest(e.a, context.Background(), u, "ua", "")
	if err != nil {
		e.t.Fatal(err)
	}
	e.users[name] = u
	e.cookies[name] = &http.Cookie{Name: "theauth_session", Value: tok}
	return u
}

func (e *tokenEnv) advance(d time.Duration) { e.clock.Add(int64(d)) }

func (e *tokenEnv) do(method, path string, body any, cookie *http.Cookie, bearer string) (*http.Response, map[string]any) {
	e.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rdr)
	req.Header.Set("Content-Type", "application/json")
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
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func (e *tokenEnv) mint(who string, abilities ...string) (string, string) {
	e.t.Helper()
	resp, out := e.do("POST", "/auth/tokens", map[string]any{"name": "t", "abilities": abilities}, e.cookies[who], "")
	if resp.StatusCode != 201 {
		e.t.Fatalf("mint as %s: %d %v", who, resp.StatusCode, out)
	}
	return out["token"].(string), out["id"].(string)
}

func TestAPITokenLifecycle(t *testing.T) {
	ctx := context.Background()
	e := newTokenEnv(t, nil)
	alice := e.addUser("alice", "read", "deploy")

	raw, tok, err := e.a.MintAPIToken(ctx, theauth.MintAPITokenInput{OwnerID: alice.ID, OwnerKind: theauth.OwnerKindUser, Name: "ci", Abilities: []string{"read"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "tk_") || tok.ExpiresAt == nil {
		t.Fatalf("unexpected token %q %+v", raw, tok)
	}

	t.Run("only the hash is stored", func(t *testing.T) {
		all, _ := e.a.ListAllAPITokens(ctx)
		for _, s := range all {
			if len(s.TokenHash) != 32 || bytes.Contains(s.TokenHash, []byte(raw)) || strings.Contains(s.Hint, raw) {
				t.Fatalf("token row leaks the secret: %+v", s)
			}
		}
	})

	t.Run("authenticate then last_used is set", func(t *testing.T) {
		p, err := e.a.AuthenticateAPIToken(ctx, raw)
		if err != nil || !p.Has("read") || p.Has("deploy") {
			t.Fatalf("principal %+v err %v", p, err)
		}
		got, _ := e.a.ListAPITokens(ctx, alice.ID)
		if got[0].LastUsedAt == nil {
			t.Fatal("last_used_at not recorded")
		}
	})

	t.Run("abilities are re-checked per request", func(t *testing.T) {
		raw2, _, _ := e.a.MintAPIToken(ctx, theauth.MintAPITokenInput{OwnerID: alice.ID, OwnerKind: theauth.OwnerKindUser, Name: "d", Abilities: []string{"read", "deploy"}})
		e.setAbilities(alice, []string{"read"})
		p, err := e.a.AuthenticateAPIToken(ctx, raw2)
		if err != nil || p.Has("deploy") || !p.Has("read") {
			t.Fatalf("demotion not applied: %+v %v", p, err)
		}
		e.setAbilities(alice, []string{"read", "deploy"})
	})

	t.Run("expiry", func(t *testing.T) {
		e.advance(2 * time.Hour)
		if _, err := e.a.AuthenticateAPIToken(ctx, raw); !errors.Is(err, theauth.ErrAPITokenInvalid) {
			t.Fatalf("expired token accepted: %v", err)
		}
	})
}

func TestAPITokenOwnerLifecycle(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		kill   func(e *tokenEnv, u theauth.User)
		wantOK bool
	}{
		{"owner disabled", func(e *tokenEnv, u theauth.User) { e.disable(u.ID) }, false},
		{"tokens revoked on delete", func(e *tokenEnv, u theauth.User) { _, _ = e.a.RevokeOwnerAPITokens(ctx, u.ID) }, false},
		{"untouched owner", func(*tokenEnv, theauth.User) {}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newTokenEnv(t, nil)
			u := e.addUser("u", "read")
			raw, _, _ := e.a.MintAPIToken(ctx, theauth.MintAPITokenInput{OwnerID: u.ID, OwnerKind: theauth.OwnerKindUser, Name: "n", Abilities: []string{"read"}})
			tc.kill(e, u)
			_, err := e.a.AuthenticateAPIToken(ctx, raw)
			if (err == nil) != tc.wantOK {
				t.Fatalf("err = %v, wantOK %v", err, tc.wantOK)
			}
		})
	}

	t.Run("owner row missing", func(t *testing.T) {
		e := newTokenEnv(t, nil)
		raw, _, _ := e.a.MintAPIToken(ctx, theauth.MintAPITokenInput{OwnerID: ulid.New(), OwnerKind: theauth.OwnerKindUser, Name: "n", Abilities: []string{"read"}})
		if _, err := e.a.AuthenticateAPIToken(ctx, raw); !errors.Is(err, theauth.ErrAPITokenInvalid) {
			t.Fatalf("token of a deleted user accepted: %v", err)
		}
	})
}

func TestAPITokenMintValidation(t *testing.T) {
	ctx := context.Background()
	e := newTokenEnv(t, func(c *theauth.APITokensConfig) { c.Abilities = []string{"read", "deploy"} })
	owner := ulid.New()
	tests := []struct {
		name string
		in   theauth.MintAPITokenInput
		want error
	}{
		{"no abilities", theauth.MintAPITokenInput{Name: "n"}, theauth.ErrAbilityInvalid},
		{"root not exclusive", theauth.MintAPITokenInput{Name: "n", Abilities: []string{"root", "read"}}, theauth.ErrAbilityInvalid},
		{"not in allowlist", theauth.MintAPITokenInput{Name: "n", Abilities: []string{"admin"}}, theauth.ErrAbilityInvalid},
		{"malformed", theauth.MintAPITokenInput{Name: "n", Abilities: []string{"Bad Name"}}, theauth.ErrAbilityInvalid},
		{"ttl too long", theauth.MintAPITokenInput{Name: "n", Abilities: []string{"read"}, TTL: 1000 * 24 * time.Hour}, theauth.ErrTokenTTLInvalid},
		{"ok root", theauth.MintAPITokenInput{Name: "n", Abilities: []string{"root"}}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.in.OwnerID, tc.in.OwnerKind = owner, theauth.OwnerKindServiceAccount
			_, _, err := e.a.MintAPIToken(ctx, tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAPITokenHTTPOwnership(t *testing.T) {
	e := newTokenEnv(t, nil)
	e.addUser("admin", "root")
	e.addUser("alice", "read", "deploy")
	e.addUser("bob", "read")

	aliceTok, aliceID := e.mint("alice", "read")
	_, bobID := e.mint("bob", "read")

	t.Run("cannot mint above own abilities", func(t *testing.T) {
		for _, ab := range []string{"root", "write"} {
			resp, _ := e.do("POST", "/auth/tokens", map[string]any{"name": "x", "abilities": []string{ab}}, e.cookies["alice"], "")
			if resp.StatusCode != 403 {
				t.Fatalf("minting %q: %d", ab, resp.StatusCode)
			}
		}
	})

	t.Run("list is owner scoped", func(t *testing.T) {
		_, out := e.do("GET", "/auth/tokens", nil, e.cookies["alice"], "")
		toks := out["tokens"].([]any)
		if len(toks) != 1 || toks[0].(map[string]any)["id"] != aliceID {
			t.Fatalf("alice sees %v", toks)
		}
		if _, ok := toks[0].(map[string]any)["TokenHash"]; ok {
			t.Fatal("hash leaked")
		}
	})

	t.Run("non-admin cannot list all", func(t *testing.T) {
		resp, _ := e.do("GET", "/auth/tokens?all=true", nil, e.cookies["alice"], "")
		if resp.StatusCode != 403 {
			t.Fatalf("got %d", resp.StatusCode)
		}
	})

	t.Run("admin lists everything", func(t *testing.T) {
		_, out := e.do("GET", "/auth/tokens?all=true", nil, e.cookies["admin"], "")
		if len(out["tokens"].([]any)) != 2 {
			t.Fatalf("admin sees %v", out)
		}
	})

	t.Run("cross-user revoke is a 404 and leaves the token live", func(t *testing.T) {
		resp, _ := e.do("DELETE", "/auth/tokens/"+bobID, nil, e.cookies["alice"], "")
		if resp.StatusCode != 404 {
			t.Fatalf("got %d", resp.StatusCode)
		}
		toks, _ := e.a.ListAPITokens(context.Background(), e.users["bob"].ID)
		if toks[0].RevokedAt != nil {
			t.Fatal("bob's token was revoked by alice")
		}
	})

	t.Run("a token cannot manage tokens", func(t *testing.T) {
		resp, _ := e.do("GET", "/auth/tokens", nil, nil, aliceTok)
		if resp.StatusCode != 401 {
			t.Fatalf("got %d", resp.StatusCode)
		}
	})

	t.Run("admin revokes anyone's token", func(t *testing.T) {
		resp, _ := e.do("DELETE", "/auth/tokens/"+bobID, nil, e.cookies["admin"], "")
		if resp.StatusCode != 204 {
			t.Fatalf("got %d", resp.StatusCode)
		}
	})

	t.Run("owner revokes own token and it stops working", func(t *testing.T) {
		resp, _ := e.do("DELETE", "/auth/tokens/"+aliceID, nil, e.cookies["alice"], "")
		if resp.StatusCode != 204 {
			t.Fatalf("got %d", resp.StatusCode)
		}
		if _, err := e.a.AuthenticateAPIToken(context.Background(), aliceTok); !errors.Is(err, theauth.ErrAPITokenInvalid) {
			t.Fatalf("revoked token accepted: %v", err)
		}
	})

	t.Run("service accounts are admin only and outlive no one", func(t *testing.T) {
		body := map[string]any{"name": "bot", "abilities": []string{"deploy"}, "service_account": true}
		if resp, _ := e.do("POST", "/auth/tokens", body, e.cookies["alice"], ""); resp.StatusCode != 403 {
			t.Fatalf("alice minted a service account token: %d", resp.StatusCode)
		}
		resp, out := e.do("POST", "/auth/tokens", body, e.cookies["admin"], "")
		if resp.StatusCode != 201 || out["ownerKind"] != theauth.OwnerKindServiceAccount {
			t.Fatalf("admin mint: %d %v", resp.StatusCode, out)
		}
		raw := out["token"].(string)
		if resp, _ := e.do("GET", "/deploy", nil, nil, raw); resp.StatusCode != 200 {
			t.Fatalf("service account token rejected: %d", resp.StatusCode)
		}
	})
}

func TestRequireAbilityMiddleware(t *testing.T) {
	e := newTokenEnv(t, nil)
	e.addUser("alice", "read", "deploy")
	deployTok, _ := e.mint("alice", "deploy")
	readTok, _ := e.mint("alice", "read")

	tests := []struct {
		name   string
		cookie *http.Cookie
		bearer string
		want   int
	}{
		{"no credentials", nil, "", 401},
		{"garbage token", nil, "tk_nope", 401},
		{"token with ability", nil, deployTok, 200},
		{"token without ability", nil, readTok, 403},
		{"session with ability", e.cookies["alice"], "", 200},
		{"bad bearer does not fall back to a good cookie", e.cookies["alice"], "tk_nope", 401},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := e.do("GET", "/deploy", nil, tc.cookie, tc.bearer)
			if resp.StatusCode != tc.want {
				t.Fatalf("got %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

func TestAPITokensRequireCapability(t *testing.T) {
	type noTokens struct{ theauth.CoreStorage }
	_, err := theauth.New(theauth.Config{
		CoreStorage: noTokens{memory.New()}, BaseURL: "http://localhost", APITokens: &theauth.APITokensConfig{},
	})
	if !errors.Is(err, theauth.ErrStorageMissingCapability) {
		t.Fatalf("err = %v", err)
	}
}

// --- device authorization grant ---

func (e *tokenEnv) deviceStart(scope string) map[string]any {
	e.t.Helper()
	form := url.Values{"client_name": {"laptop"}}
	if scope != "" {
		form.Set("scope", scope)
	}
	resp, err := http.PostForm(e.srv.URL+"/auth/device/code", form)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 200 {
		e.t.Fatalf("device start: %d %v", resp.StatusCode, out)
	}
	return out
}

func (e *tokenEnv) devicePoll(code string) (int, map[string]any) {
	e.t.Helper()
	resp, err := http.PostForm(e.srv.URL+"/auth/device/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {code}})
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *tokenEnv) deviceApprove(who, userCode, action string, abilities ...string) int {
	e.t.Helper()
	resp, _ := e.do("POST", "/auth/device/approve", map[string]any{"user_code": userCode, "action": action, "abilities": abilities}, e.cookies[who], "")
	return resp.StatusCode
}

func TestDeviceGrantFlow(t *testing.T) {
	e := newTokenEnv(t, nil)
	e.addUser("admin", "root")
	e.addUser("bob", "read")

	t.Run("pending then approved then minted and capped", func(t *testing.T) {
		start := e.deviceStart("read deploy")
		uc := start["user_code"].(string)
		if len(uc) != 9 || uc[4] != '-' || start["interval"] == nil || !strings.Contains(start["verification_uri_complete"].(string), "user_code=") {
			t.Fatalf("bad start response %v", start)
		}
		code := start["device_code"].(string)
		if status, out := e.devicePoll(code); status != 400 || out["error"] != "authorization_pending" {
			t.Fatalf("pre-approval poll: %d %v", status, out)
		}
		if got := e.deviceApprove("bob", strings.ToLower(uc), "approve"); got != 204 {
			t.Fatalf("approve: %d", got)
		}
		status, out := e.devicePoll(code)
		if status != 200 || out["token_type"] != "Bearer" || out["scope"] != "read" || out["expires_in"].(float64) <= 0 {
			t.Fatalf("redeem: %d %v (bob holds only read, deploy must be dropped)", status, out)
		}
		if status, out := e.devicePoll(code); status != 400 || out["error"] != "invalid_grant" {
			t.Fatalf("second redeem: %d %v", status, out)
		}
		toks, _ := e.a.ListAPITokens(context.Background(), e.users["bob"].ID)
		if len(toks) != 1 || toks[0].ExpiresAt == nil {
			t.Fatalf("minted token must expire: %+v", toks)
		}
	})

	t.Run("root is never silent", func(t *testing.T) {
		start := e.deviceStart("root")
		if got := e.deviceApprove("bob", start["user_code"].(string), "approve"); got != 403 {
			t.Fatalf("non-root approver granted root: %d", got)
		}
		start = e.deviceStart("root")
		if got := e.deviceApprove("admin", start["user_code"].(string), "approve"); got != 204 {
			t.Fatalf("root approver: %d", got)
		}
		if _, out := e.devicePoll(start["device_code"].(string)); out["scope"] != "root" {
			t.Fatalf("explicit root by root approver: %v", out)
		}
	})

	t.Run("approver can narrow but not widen", func(t *testing.T) {
		start := e.deviceStart("read deploy")
		if got := e.deviceApprove("admin", start["user_code"].(string), "approve", "write"); got != 400 {
			t.Fatalf("widening accepted: %d", got)
		}
		if got := e.deviceApprove("admin", start["user_code"].(string), "approve", "deploy"); got != 204 {
			t.Fatalf("narrowing failed: %d", got)
		}
		if _, out := e.devicePoll(start["device_code"].(string)); out["scope"] != "deploy" {
			t.Fatalf("scope = %v", out["scope"])
		}
	})

	t.Run("deny", func(t *testing.T) {
		start := e.deviceStart("")
		if got := e.deviceApprove("bob", start["user_code"].(string), "deny"); got != 204 {
			t.Fatalf("deny: %d", got)
		}
		if status, out := e.devicePoll(start["device_code"].(string)); status != 400 || out["error"] != "access_denied" {
			t.Fatalf("poll after deny: %d %v", status, out)
		}
	})

	t.Run("expired", func(t *testing.T) {
		start := e.deviceStart("read")
		e.advance(11 * time.Minute)
		if status, out := e.devicePoll(start["device_code"].(string)); status != 400 || out["error"] != "expired_token" {
			t.Fatalf("expired poll: %d %v", status, out)
		}
		if got := e.deviceApprove("bob", start["user_code"].(string), "approve"); got != 410 {
			t.Fatalf("approve expired: %d", got)
		}
	})

	t.Run("approve needs a session", func(t *testing.T) {
		start := e.deviceStart("read")
		resp, _ := e.do("POST", "/auth/device/approve", map[string]any{"user_code": start["user_code"]}, nil, "")
		if resp.StatusCode != 401 {
			t.Fatalf("got %d", resp.StatusCode)
		}
	})

	t.Run("unknown or empty abilities are rejected at start", func(t *testing.T) {
		e2 := newTokenEnv(t, func(c *theauth.APITokensConfig) { c.Device = &theauth.DeviceConfig{} })
		resp, err := http.PostForm(e2.srv.URL+"/auth/device/code", url.Values{})
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("got %d", resp.StatusCode)
		}
	})
}

func TestDeviceSlowDown(t *testing.T) {
	e := newTokenEnv(t, func(c *theauth.APITokensConfig) {
		c.Device = &theauth.DeviceConfig{Interval: 5 * time.Second, DefaultAbilities: []string{"read"}}
	})
	start := e.deviceStart("")
	code := start["device_code"].(string)
	if _, out := e.devicePoll(code); out["error"] != "authorization_pending" {
		t.Fatalf("first poll: %v", out)
	}
	if _, out := e.devicePoll(code); out["error"] != "slow_down" {
		t.Fatalf("immediate re-poll: %v", out)
	}
	e.advance(6 * time.Second)
	if _, out := e.devicePoll(code); out["error"] != "slow_down" {
		t.Fatalf("poll after only the old interval must still be slowed: %v", out)
	}
	e.advance(16 * time.Second)
	if _, out := e.devicePoll(code); out["error"] != "authorization_pending" {
		t.Fatalf("poll after the widened interval: %v", out)
	}
}

func TestDeviceUserCodeAttemptsAreLimited(t *testing.T) {
	e := newTokenEnv(t, nil)
	e.addUser("bob", "read")
	start := e.deviceStart("read")
	for i := range 5 {
		if got := e.deviceApprove("bob", "BBBBBBB"+string(rune('C'+i)), "approve"); got != 404 {
			t.Fatalf("guess %d: %d", i, got)
		}
	}
	if got := e.deviceApprove("bob", start["user_code"].(string), "approve"); got != 429 {
		t.Fatalf("correct code after budget spent: %d, want 429", got)
	}
}

func TestDeviceConcurrentRedeemMintsOnce(t *testing.T) {
	e := newTokenEnv(t, nil)
	bob := e.addUser("bob", "read")
	start := e.deviceStart("read")
	if got := e.deviceApprove("bob", start["user_code"].(string), "approve"); got != 204 {
		t.Fatalf("approve: %d", got)
	}
	code := start["device_code"].(string)

	const workers = 32
	var wg sync.WaitGroup
	var minted atomic.Int32
	gate := make(chan struct{})
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			if _, err := e.a.RedeemDeviceCode(context.Background(), code); err == nil {
				minted.Add(1)
			}
		}()
	}
	close(gate)
	wg.Wait()
	if minted.Load() != 1 {
		t.Fatalf("%d polls minted a token, want exactly 1", minted.Load())
	}
	toks, _ := e.a.ListAPITokens(context.Background(), bob.ID)
	if len(toks) != 1 {
		t.Fatalf("%d tokens stored, want 1", len(toks))
	}
}
