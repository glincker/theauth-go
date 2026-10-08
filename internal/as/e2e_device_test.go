package as_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

// e2e_device_test.go: the RFC 8628 device grant against the real router, memory
// store and an injected clock (no sleeps).

type deviceHarness struct {
	t        *testing.T
	auth     *theauth.TheAuth
	store    *memory.Store
	srv      *httptest.Server
	clock    *fakeClock
	cookie   *http.Cookie
	user     theauth.User
	clientID string
}

func newDeviceHarness(t *testing.T, mut ...func(*theauth.AuthorizationServerConfig)) *deviceHarness {
	t.Helper()
	clock := newFakeClock(time.Now())
	h := &deviceHarness{t: t, clock: clock}
	h.auth, h.store = newASInstance(t, append([]func(*theauth.AuthorizationServerConfig){func(c *theauth.AuthorizationServerConfig) {
		c.Clock = clock
		c.RegistrationTokens = []string{"static-token"}
		c.DeviceAuthorization = &theauth.DeviceAuthorizationConfig{CSS: "body{--accent:teal}"}
	}}, mut...)...)

	h.user = theauth.User{ID: ulid.New(), Email: "dev@example.com"}
	if _, err := h.store.CreateUser(context.Background(), h.user); err != nil {
		t.Fatal(err)
	}
	raw, _ := crypto.NewToken()
	if _, err := h.store.CreateSession(context.Background(), theauth.Session{
		ID: ulid.New(), UserID: h.user.ID, TokenHash: crypto.HashToken(raw),
		AuthLevel: theauth.AuthLevelFull, ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	h.cookie = &http.Cookie{Name: "theauth_session", Value: raw}

	r := chi.NewRouter()
	h.auth.Mount(r)
	h.srv = httptest.NewServer(r)
	t.Cleanup(h.srv.Close)
	h.clientID = h.register(`{"client_name":"Deploy CLI","grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],"token_endpoint_auth_method":"none"}`)
	return h
}

func (h *deviceHarness) register(body string) string {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer static-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		h.t.Fatalf("register: %d %s", resp.StatusCode, b)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	_ = json.Unmarshal(b, &out)
	return out.ClientID
}

func (h *deviceHarness) postForm(path string, form url.Values, cookie bool) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie {
		req.AddCookie(h.cookie)
	}
	return h.do(req)
}

func (h *deviceHarness) do(req *http.Request) (int, map[string]any) {
	h.t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

func (h *deviceHarness) start() map[string]any {
	h.t.Helper()
	code, body := h.postForm("/oauth/device_authorization", url.Values{
		"client_id": {h.clientID}, "scope": {"files.read"}, "resource": {"https://files.example.com/mcp"},
	}, false)
	if code != http.StatusOK {
		h.t.Fatalf("device_authorization: %d %v", code, body)
	}
	return body
}

func (h *deviceHarness) poll(deviceCode string) (int, map[string]any) {
	return h.postForm("/oauth/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":  {h.clientID}, "device_code": {deviceCode},
	}, false)
}

func (h *deviceHarness) decide(userCode, action string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/oauth/device",
		strings.NewReader(`{"user_code":"`+userCode+`","action":"`+action+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(h.cookie)
	return h.do(req)
}

func TestDeviceGrantHappyPath(t *testing.T) {
	h := newDeviceHarness(t)
	start := h.start()
	for _, k := range []string{"device_code", "user_code", "verification_uri", "verification_uri_complete", "expires_in", "interval"} {
		if _, ok := start[k]; !ok {
			t.Fatalf("response missing %q: %v", k, start)
		}
	}
	deviceCode, userCode := start["device_code"].(string), start["user_code"].(string)
	if !strings.Contains(start["verification_uri_complete"].(string), url.QueryEscape(userCode)) {
		t.Fatalf("verification_uri_complete does not carry the code: %v", start)
	}

	code, body := h.poll(deviceCode)
	if code != 400 || body["error"] != "authorization_pending" {
		t.Fatalf("first poll: %d %v", code, body)
	}
	h.clock.Advance(6 * time.Second)

	if code, body := h.decide(userCode, "approve"); code != 200 || body["status"] != "approved" {
		t.Fatalf("approve: %d %v", code, body)
	}
	code, tok := h.poll(deviceCode)
	if code != 200 || tok["access_token"] == "" || tok["access_token"] == nil || tok["refresh_token"] == nil {
		t.Fatalf("token poll: %d %v", code, tok)
	}
	if tok["token_type"] != "Bearer" || tok["scope"] != "files.read" {
		t.Fatalf("token response: %v", tok)
	}

	h.clock.Advance(6 * time.Second)
	if code, body := h.poll(deviceCode); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("device_code must be single use: %d %v", code, body)
	}
}

func TestDeviceGrantPollingErrors(t *testing.T) {
	steps := []struct {
		name    string
		setup   func(h *deviceHarness, userCode string)
		advance time.Duration
		want    string
	}{
		{"pending after the interval", func(*deviceHarness, string) {}, 6 * time.Second, "authorization_pending"},
		{"too fast", func(*deviceHarness, string) {}, 0, "slow_down"},
		{"denied", func(h *deviceHarness, uc string) { h.decide(uc, "deny") }, 6 * time.Second, "access_denied"},
		{"expired", func(*deviceHarness, string) {}, 11 * time.Minute, "expired_token"},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			h := newDeviceHarness(t)
			start := h.start()
			dc := start["device_code"].(string)
			if code, body := h.poll(dc); code != 400 || body["error"] != "authorization_pending" {
				t.Fatalf("priming poll: %d %v", code, body)
			}
			st.setup(h, start["user_code"].(string))
			h.clock.Advance(st.advance)
			code, body := h.poll(dc)
			if code != 400 || body["error"] != st.want {
				t.Fatalf("got %d %v, want %s", code, body, st.want)
			}
		})
	}

	t.Run("slow_down widens the interval by 5 seconds", func(t *testing.T) {
		h := newDeviceHarness(t)
		dc := h.start()["device_code"].(string)
		h.poll(dc)
		if _, body := h.poll(dc); body["error"] != "slow_down" {
			t.Fatalf("want slow_down, got %v", body)
		}
		// The old 5s interval has passed but the new 10s one has not.
		h.clock.Advance(6 * time.Second)
		if _, body := h.poll(dc); body["error"] != "slow_down" {
			t.Fatalf("interval should now be 10s, got %v", body)
		}
		h.clock.Advance(16 * time.Second)
		if _, body := h.poll(dc); body["error"] != "authorization_pending" {
			t.Fatalf("want pending after waiting, got %v", body)
		}
	})
}

func TestDeviceCodesAreHashedAtRest(t *testing.T) {
	h := newDeviceHarness(t)
	start := h.start()
	dc, uc := start["device_code"].(string), start["user_code"].(string)
	plain := sha256.Sum256([]byte(dc))
	if _, err := h.store.DeviceAuthorizationByDeviceCodeHash(context.Background(), plain[:]); err == nil {
		t.Fatal("device_code stored as a plain sha256: a leaked table would expose live codes")
	}
	normalized := strings.ReplaceAll(uc, "-", "")
	plainUser := sha256.Sum256([]byte(normalized))
	if _, err := h.store.DeviceAuthorizationByUserCodeHash(context.Background(), plainUser[:]); err == nil {
		t.Fatal("user_code stored as a plain sha256: it is brute-forceable offline")
	}
}

func TestDeviceStartValidation(t *testing.T) {
	h := newDeviceHarness(t)
	noDevice := h.register(`{"redirect_uris":["https://app.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	cases := []struct {
		name   string
		form   url.Values
		status int
		errStr string
	}{
		{"client without the device grant", url.Values{"client_id": {noDevice}, "scope": {"files.read"}, "resource": {"https://files.example.com/mcp"}}, 400, "unauthorized_client"},
		{"unknown client", url.Values{"client_id": {"nope"}, "scope": {"files.read"}}, 401, "invalid_client"},
		{"scope outside the resource", url.Values{"client_id": {h.clientID}, "scope": {"admin"}, "resource": {"https://files.example.com/mcp"}}, 400, "invalid_scope"},
		{"missing scope", url.Values{"client_id": {h.clientID}, "resource": {"https://files.example.com/mcp"}}, 400, "invalid_scope"},
		{"unknown resource", url.Values{"client_id": {h.clientID}, "scope": {"files.read"}, "resource": {"https://elsewhere.example"}}, 400, "invalid_target"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := h.postForm("/oauth/device_authorization", tc.form, false)
			if code != tc.status || body["error"] != tc.errStr {
				t.Fatalf("got %d %v, want %d %s", code, body, tc.status, tc.errStr)
			}
		})
	}
}

func TestDeviceVerificationPage(t *testing.T) {
	h := newDeviceHarness(t, func(c *theauth.AuthorizationServerConfig) {
		c.DeviceAuthorization.MaxVerifyAttempts = 3
	})
	start := h.start()
	uc := start["user_code"].(string)

	get := func(path string, cookie bool, accept string) (*http.Response, string) {
		req, _ := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
		if cookie {
			req.AddCookie(h.cookie)
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	t.Run("anonymous browsers are sent to sign in and back", func(t *testing.T) {
		resp, _ := get("/oauth/device?user_code="+url.QueryEscape(uc), false, "")
		loc := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusFound || !strings.Contains(loc, "/login?next=") || !strings.Contains(loc, "device") {
			t.Fatalf("got %d %q", resp.StatusCode, loc)
		}
	})
	t.Run("anonymous JSON callers get 401", func(t *testing.T) {
		resp, _ := get("/oauth/device", false, "application/json")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("got %d", resp.StatusCode)
		}
	})
	t.Run("entry form without a code", func(t *testing.T) {
		resp, body := get("/oauth/device", true, "")
		if resp.StatusCode != 200 || !strings.Contains(body, `name="user_code"`) {
			t.Fatalf("got %d %s", resp.StatusCode, body)
		}
	})
	t.Run("confirm page names the client and sets safe headers", func(t *testing.T) {
		resp, body := get("/oauth/device?user_code="+url.QueryEscape(strings.ToLower(uc)), true, "")
		if resp.StatusCode != 200 || !strings.Contains(body, "Deploy CLI") || !strings.Contains(body, "files.read") ||
			!strings.Contains(body, `value="approve"`) || !strings.Contains(body, "--accent:teal") {
			t.Fatalf("got %d %s", resp.StatusCode, body)
		}
		if resp.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
			resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("missing hardening headers: %v", resp.Header)
		}
	})
	t.Run("viewing the page never approves", func(t *testing.T) {
		if code, body := h.poll(start["device_code"].(string)); code != 400 || body["error"] != "authorization_pending" {
			t.Fatalf("GET must not decide: %d %v", code, body)
		}
	})
	t.Run("attempts are limited per user", func(t *testing.T) {
		// Two attempts were already spent above (confirm page, entry form does not count).
		var last int
		for i := 0; i < 4; i++ {
			resp, _ := get("/oauth/device?user_code=BBBB-BBBB", true, "application/json")
			last = resp.StatusCode
		}
		if last != http.StatusTooManyRequests {
			t.Fatalf("last status %d, want 429", last)
		}
	})
}

func TestDeviceMetadata(t *testing.T) {
	h := newDeviceHarness(t)
	resp, err := http.Get(h.srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc struct {
		Endpoint string   `json:"device_authorization_endpoint"`
		Grants   []string `json:"grant_types_supported"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if doc.Endpoint != "https://auth.example.com/oauth/device_authorization" {
		t.Fatalf("endpoint = %q", doc.Endpoint)
	}
	found := false
	for _, g := range doc.Grants {
		found = found || g == "urn:ietf:params:oauth:grant-type:device_code"
	}
	if !found {
		t.Fatalf("grant not advertised: %v", doc.Grants)
	}
}

func TestDeviceDisabledByDefault(t *testing.T) {
	a, _ := newASInstance(t)
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/oauth/device_authorization", "application/x-www-form-urlencoded", strings.NewReader("client_id=x"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_ = rand.Reader
}
