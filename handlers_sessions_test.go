package theauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
)

const sessTestPassword = "twelve-chars-min-pw"

type sessFixture struct {
	a     *theauth.TheAuth
	store *memory.Store
	srv   *httptest.Server
	user  theauth.User
}

func newSessFixture(t *testing.T, mutate func(*theauth.Config)) sessFixture {
	t.Helper()
	store := memory.New()
	cfg := theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		SessionTTL:        time.Hour,
		RateLimitPerIP:    1000,
		RateLimitPerEmail: 1000,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := theauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	r := chi.NewRouter()
	a.Mount(r)
	r.With(a.RequireRecentAuth(time.Minute)).Get("/sensitive", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	user := mkSessUser(t, store, "sess@example.test")
	hash, err := crypto.HashPassword(sessTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetUserPassword(context.Background(), user.ID, hash); err != nil {
		t.Fatal(err)
	}
	return sessFixture{a: a, store: store, srv: srv, user: user}
}

func mkSessUser(t *testing.T, store *memory.Store, email string) theauth.User {
	t.Helper()
	u, err := store.CreateUser(context.Background(), theauth.User{ID: ulid.New(), Email: email, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

type seedOpts struct {
	ua, ip   string
	age      time.Duration
	lastSeen time.Duration
}

func (f sessFixture) seed(t *testing.T, user theauth.User, tag string, o seedOpts) theauth.Session {
	t.Helper()
	created := time.Now().Add(-o.age)
	last := time.Now().Add(-o.lastSeen)
	s, err := f.store.CreateSession(context.Background(), theauth.Session{
		ID: ulid.New(), UserID: user.ID, TokenHash: crypto.HashToken(tag), UserAgent: o.ua, IP: o.ip,
		CreatedAt: created, LastSeenAt: last, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f sessFixture) do(t *testing.T, method, path, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.AddCookie(&http.Cookie{Name: "theauth_session", Value: token})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func (f sessFixture) status(t *testing.T, method, path, token string, body any) int {
	t.Helper()
	resp, _ := f.do(t, method, path, token, body)
	return resp.StatusCode
}

func TestSessionListShowsDeviceCurrentAndPrefix(t *testing.T) {
	f := newSessFixture(t, nil)
	chromeMac := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	iphone := "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1"
	cur := f.seed(t, f.user, "tok-cur", seedOpts{ua: chromeMac, ip: "203.0.113.77", age: time.Minute})
	f.seed(t, f.user, "tok-phone", seedOpts{ua: iphone, ip: "2001:db8:abcd:1::5", age: time.Hour})
	other := mkSessUser(t, f.store, "other@example.test")
	f.seed(t, other, "tok-foreign", seedOpts{ua: "curl/8.0", age: time.Minute})

	resp, body := f.do(t, "GET", "/auth/sessions", "tok-cur", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	var out struct {
		Sessions []theauth.SessionInfo `json:"sessions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sessions) != 2 {
		t.Fatalf("want 2 sessions, got %d: %s", len(out.Sessions), body)
	}
	first, second := out.Sessions[0], out.Sessions[1]
	if first.ID != cur.ID || !first.Current || first.DeviceLabel != "Chrome on macOS" || first.IPPrefix != "203.0.113.0/24" {
		t.Fatalf("first row wrong: %+v", first)
	}
	if second.Current || second.DeviceLabel != "Safari on iOS" || second.IPPrefix != "2001:db8:abcd::/48" {
		t.Fatalf("second row wrong: %+v", second)
	}
	if f.status(t, "GET", "/auth/sessions", "", nil) != http.StatusUnauthorized {
		t.Fatal("anonymous list must be 401")
	}
}

func TestSessionRevokeByID(t *testing.T) {
	f := newSessFixture(t, nil)
	other := mkSessUser(t, f.store, "other@example.test")
	cur := f.seed(t, f.user, "tok-cur", seedOpts{})
	mine := f.seed(t, f.user, "tok-mine", seedOpts{})
	foreign := f.seed(t, other, "tok-foreign", seedOpts{})
	tests := []struct {
		name   string
		id     string
		want   int
		revoke string
	}{
		{"foreign session is not found", foreign.ID.String(), http.StatusNotFound, ""},
		{"malformed id is not found", "nope", http.StatusNotFound, ""},
		{"unknown id is not found", ulid.New().String(), http.StatusNotFound, ""},
		{"own other session", mine.ID.String(), http.StatusNoContent, "tok-mine"},
		{"own current session", cur.ID.String(), http.StatusNoContent, "tok-cur"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := f.status(t, "DELETE", "/auth/sessions/"+tc.id, "tok-cur", nil); got != tc.want && tc.revoke != "tok-cur" {
				t.Fatalf("status %d want %d", got, tc.want)
			}
		})
	}
	for tok, want := range map[string]int{"tok-mine": http.StatusUnauthorized, "tok-cur": http.StatusUnauthorized, "tok-foreign": http.StatusOK} {
		if got := f.status(t, "GET", "/auth/me", tok, nil); got != want {
			t.Errorf("/auth/me with %s = %d, want %d", tok, got, want)
		}
	}
}

func TestSessionRevokeOthers(t *testing.T) {
	f := newSessFixture(t, nil)
	f.seed(t, f.user, "tok-cur", seedOpts{})
	f.seed(t, f.user, "tok-a", seedOpts{})
	f.seed(t, f.user, "tok-b", seedOpts{})
	other := mkSessUser(t, f.store, "other@example.test")
	f.seed(t, other, "tok-foreign", seedOpts{})

	resp, body := f.do(t, "POST", "/auth/sessions/revoke-others", "tok-cur", nil)
	if resp.StatusCode != http.StatusOK || string(bytes.TrimSpace(body)) != `{"revoked":2}` {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	for tok, want := range map[string]int{"tok-cur": 200, "tok-a": 401, "tok-b": 401, "tok-foreign": 200} {
		if got := f.status(t, "GET", "/auth/me", tok, nil); got != want {
			t.Errorf("/auth/me with %s = %d, want %d", tok, got, want)
		}
	}
}

func TestIdleTimeoutAndLastSeenTouch(t *testing.T) {
	f := newSessFixture(t, func(c *theauth.Config) {
		c.SessionIdleTimeout = time.Hour
		c.SessionTouchInterval = time.Minute
	})
	f.seed(t, f.user, "tok-idle", seedOpts{age: 3 * time.Hour, lastSeen: 2 * time.Hour})
	stale := f.seed(t, f.user, "tok-stale", seedOpts{age: 3 * time.Hour, lastSeen: 10 * time.Minute})
	fresh := f.seed(t, f.user, "tok-fresh", seedOpts{lastSeen: time.Second})

	if got := f.status(t, "GET", "/auth/me", "tok-idle", nil); got != http.StatusUnauthorized {
		t.Fatalf("idle-expired session = %d, want 401", got)
	}
	if got := f.status(t, "GET", "/auth/me", "tok-stale", nil); got != http.StatusOK {
		t.Fatalf("within-idle session = %d, want 200", got)
	}
	gotStale, _ := f.store.SessionByID(context.Background(), stale.ID)
	if time.Since(gotStale.LastSeenAt) > 5*time.Second {
		t.Fatalf("LastSeenAt not touched: %v", gotStale.LastSeenAt)
	}
	f.status(t, "GET", "/auth/me", "tok-fresh", nil)
	gotFresh, _ := f.store.SessionByID(context.Background(), fresh.ID)
	if !gotFresh.LastSeenAt.Equal(fresh.LastSeenAt) {
		t.Fatal("LastSeenAt written inside the throttle interval")
	}

	resp, body := f.do(t, "GET", "/auth/sessions", "tok-stale", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	var out struct{ Sessions []theauth.SessionInfo }
	_ = json.Unmarshal(body, &out)
	if len(out.Sessions) != 2 {
		t.Fatalf("idle-expired session must not be listed, got %d rows", len(out.Sessions))
	}
}

type coreOnlyStore struct{ theauth.CoreStorage }

func TestSessionConfigValidation(t *testing.T) {
	cfgBase := func() theauth.Config {
		return theauth.Config{CoreStorage: coreOnlyStore{memory.New()}, BaseURL: "http://localhost"}
	}
	tests := []struct {
		name    string
		mutate  func(*theauth.Config)
		wantErr error
		wantMsg string
	}{
		{"idle needs capability", func(c *theauth.Config) { c.SessionIdleTimeout = time.Hour }, theauth.ErrStorageMissingCapability, ""},
		{"links need capability", func(c *theauth.Config) {
			c.SessionLinks = &theauth.SessionLinksConfig{CredentialChecker: theauth.CredentialCheckerFunc(func(context.Context, string) error { return nil })}
		}, theauth.ErrStorageMissingCapability, ""},
		{"core only without features is fine", func(*theauth.Config) {}, nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfgBase()
			tc.mutate(&cfg)
			a, err := theauth.New(cfg)
			if a != nil {
				a.Close()
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
	full := []struct {
		name   string
		mutate func(*theauth.Config)
	}{
		{"touch not shorter than idle", func(c *theauth.Config) { c.SessionIdleTimeout = time.Minute; c.SessionTouchInterval = time.Hour }},
		{"negative idle", func(c *theauth.Config) { c.SessionIdleTimeout = -time.Second }},
		{"links without checker", func(c *theauth.Config) { c.SessionLinks = &theauth.SessionLinksConfig{} }},
	}
	for _, tc := range full {
		t.Run(tc.name, func(t *testing.T) {
			cfg := theauth.Config{Storage: memory.New(), BaseURL: "http://localhost"}
			tc.mutate(&cfg)
			if a, err := theauth.New(cfg); err == nil {
				a.Close()
				t.Fatal("want error")
			}
		})
	}
}

func TestStepUpAndRecentAuth(t *testing.T) {
	f := newSessFixture(t, nil)
	f.seed(t, f.user, "tok-old", seedOpts{age: 10 * time.Minute})
	f.seed(t, f.user, "tok-new", seedOpts{age: time.Second})

	if got := f.status(t, "GET", "/sensitive", "tok-old", nil); got != http.StatusForbidden {
		t.Fatalf("old session /sensitive = %d, want 403", got)
	}
	if got := f.status(t, "GET", "/sensitive", "tok-new", nil); got != http.StatusNoContent {
		t.Fatalf("fresh login /sensitive = %d, want 204", got)
	}
	if got := f.status(t, "GET", "/sensitive", "", nil); got != http.StatusUnauthorized {
		t.Fatalf("anonymous /sensitive = %d, want 401", got)
	}

	tests := []struct {
		name string
		body map[string]string
		want int
	}{
		{"wrong password", map[string]string{"method": "password", "password": "wrong-password-xx"}, http.StatusUnauthorized},
		{"unknown method", map[string]string{"method": "sms"}, http.StatusUnauthorized},
		{"totp not configured", map[string]string{"method": "totp", "code": "123456"}, http.StatusUnauthorized},
		{"passkey not configured", map[string]string{"method": "passkey"}, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := f.status(t, "POST", "/auth/step-up", "tok-old", tc.body); got != tc.want {
				t.Fatalf("status %d want %d", got, tc.want)
			}
			if got := f.status(t, "GET", "/sensitive", "tok-old", nil); got != http.StatusForbidden {
				t.Fatalf("failed step-up must not elevate; /sensitive = %d", got)
			}
		})
	}

	resp, body := f.do(t, "POST", "/auth/step-up", "tok-old", map[string]string{"method": "password", "password": sessTestPassword})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("step-up status %d body %s", resp.StatusCode, body)
	}
	if got := f.status(t, "GET", "/sensitive", "tok-old", nil); got != http.StatusNoContent {
		t.Fatalf("elevated /sensitive = %d, want 204", got)
	}
	if got := f.status(t, "GET", "/auth/me", "tok-old", nil); got != http.StatusOK {
		t.Fatalf("elevated session must stay valid, /auth/me = %d", got)
	}
}

func TestElevationExpires(t *testing.T) {
	f := newSessFixture(t, func(c *theauth.Config) { c.StepUpTTL = time.Minute })
	s := f.seed(t, f.user, "tok", seedOpts{age: time.Hour})
	past := time.Now().Add(-time.Second)
	if err := f.store.SetSessionElevatedUntil(context.Background(), s.ID, &past); err != nil {
		t.Fatal(err)
	}
	if got := f.status(t, "GET", "/sensitive", "tok", nil); got != http.StatusForbidden {
		t.Fatalf("expired elevation /sensitive = %d, want 403", got)
	}
	soon := time.Now().Add(30 * time.Second)
	if err := f.store.SetSessionElevatedUntil(context.Background(), s.ID, &soon); err != nil {
		t.Fatal(err)
	}
	if got := f.status(t, "GET", "/sensitive", "tok", nil); got != http.StatusNoContent {
		t.Fatalf("live elevation /sensitive = %d, want 204", got)
	}
}

func TestChangePasswordRotatesAndRevokesOthers(t *testing.T) {
	f := newSessFixture(t, nil)
	f.seed(t, f.user, "tok-cur", seedOpts{})
	f.seed(t, f.user, "tok-other", seedOpts{})
	newPW := "a-brand-new-password-1"

	tests := []struct {
		name string
		body map[string]string
		want int
	}{
		{"wrong current", map[string]string{"currentPassword": "nope-nope-nope-1", "newPassword": newPW}, http.StatusUnauthorized},
		{"weak new", map[string]string{"currentPassword": sessTestPassword, "newPassword": "short"}, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := f.status(t, "POST", "/auth/password/change", "tok-cur", tc.body); got != tc.want {
				t.Fatalf("status %d want %d", got, tc.want)
			}
		})
	}
	if got := f.status(t, "GET", "/auth/me", "tok-other", nil); got != 200 {
		t.Fatal("failed changes must not revoke sessions")
	}

	resp, _ := f.do(t, "POST", "/auth/password/change", "tok-cur", map[string]string{"currentPassword": sessTestPassword, "newPassword": newPW})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("change status %d", resp.StatusCode)
	}
	var fresh string
	for _, c := range resp.Cookies() {
		if c.Name == "theauth_session" {
			fresh = c.Value
		}
	}
	if fresh == "" || fresh == "tok-cur" {
		t.Fatalf("expected a rotated session cookie, got %q", fresh)
	}
	for tok, want := range map[string]int{"tok-cur": 401, "tok-other": 401, fresh: 200} {
		if got := f.status(t, "GET", "/auth/me", tok, nil); got != want {
			t.Errorf("/auth/me with %q = %d, want %d", tok, got, want)
		}
	}
}

type credSet struct {
	mu      sync.Mutex
	revoked map[string]bool
	err     error
	calls   int
}

func (c *credSet) CheckCredential(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.err != nil {
		return c.err
	}
	if c.revoked[id] {
		return theauth.ErrCredentialRevoked
	}
	return nil
}

func (c *credSet) revoke(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revoked[id] = true
}

func newLinkFixture(t *testing.T) (sessFixture, *credSet) {
	t.Helper()
	creds := &credSet{revoked: map[string]bool{}}
	f := newSessFixture(t, func(c *theauth.Config) {
		c.SessionLinks = &theauth.SessionLinksConfig{TTL: time.Minute, CredentialChecker: creds}
	})
	return f, creds
}

func cookieValue(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == "theauth_session" {
			return c.Value
		}
	}
	return ""
}

func TestSessionLinkRoundTripAndPerUseRecheck(t *testing.T) {
	f, creds := newLinkFixture(t)
	ctx := context.Background()
	tok, _, err := f.a.MintSessionLink(ctx, theauth.MintSessionLinkInput{UserID: f.user.ID, CredentialID: "api-token-1"})
	if err != nil {
		t.Fatal(err)
	}
	resp, body := f.do(t, "POST", "/auth/session-link/consume", "", map[string]string{"token": tok})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("consume status %d body %s", resp.StatusCode, body)
	}
	sess := cookieValue(resp)
	if sess == "" {
		t.Fatal("no session cookie")
	}
	if got := f.status(t, "POST", "/auth/session-link/consume", "", map[string]string{"token": tok}); got != http.StatusUnauthorized {
		t.Fatalf("second consume = %d, want 401 (one time)", got)
	}
	creds.mu.Lock()
	before := creds.calls
	creds.mu.Unlock()
	for i := 0; i < 3; i++ {
		if got := f.status(t, "GET", "/auth/me", sess, nil); got != http.StatusOK {
			t.Fatalf("linked session /auth/me = %d", got)
		}
	}
	creds.mu.Lock()
	rechecks := creds.calls - before
	creds.mu.Unlock()
	if rechecks != 3 {
		t.Fatalf("credential re-checked %d times over 3 uses, want 3", rechecks)
	}
	if got := f.status(t, "GET", "/sensitive", sess, nil); got != http.StatusForbidden {
		t.Fatalf("link session must not count as a fresh login; /sensitive = %d", got)
	}

	creds.revoke("api-token-1")
	if got := f.status(t, "GET", "/auth/me", sess, nil); got != http.StatusUnauthorized {
		t.Fatalf("session after credential revocation = %d, want 401", got)
	}
	s, _, err := theauth.ValidateSessionForTest(f.a, ctx, sess)
	if err == nil || s != nil {
		t.Fatalf("Authenticate after revocation = %v, %v", s, err)
	}
}

func TestSessionLinkFailureModes(t *testing.T) {
	f, creds := newLinkFixture(t)
	ctx := context.Background()

	if _, _, err := f.a.MintSessionLink(ctx, theauth.MintSessionLinkInput{UserID: ulid.New()}); err == nil {
		t.Fatal("mint for unknown user must fail")
	}
	creds.revoke("dead")
	if _, _, err := f.a.MintSessionLink(ctx, theauth.MintSessionLinkInput{UserID: f.user.ID, CredentialID: "dead"}); !errors.Is(err, theauth.ErrCredentialRevoked) {
		t.Fatalf("mint with revoked credential: %v", err)
	}

	tests := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{"unknown token", func(*testing.T) string { return "not-a-real-token" }},
		{"expired link", func(t *testing.T) string {
			tok, _, err := f.a.MintSessionLink(ctx, theauth.MintSessionLinkInput{UserID: f.user.ID, TTL: time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(5 * time.Millisecond)
			return tok
		}},
		{"credential revoked after mint", func(t *testing.T) string {
			tok, _, err := f.a.MintSessionLink(ctx, theauth.MintSessionLinkInput{UserID: f.user.ID, CredentialID: "later"})
			if err != nil {
				t.Fatal(err)
			}
			creds.revoke("later")
			return tok
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok := tc.setup(t)
			if got := f.status(t, "POST", "/auth/session-link/consume", "", map[string]string{"token": tok}); got != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401", got)
			}
			if _, _, err := f.a.ConsumeSessionLink(ctx, tok, "", ""); !errors.Is(err, theauth.ErrSessionLinkInvalid) {
				t.Fatalf("err = %v, want ErrSessionLinkInvalid", err)
			}
		})
	}
	if got := f.status(t, "POST", "/auth/session-link/consume", "", map[string]string{"token": ""}); got != http.StatusBadRequest {
		t.Fatalf("empty token = %d, want 400", got)
	}

	tok, _, _ := f.a.MintSessionLink(ctx, theauth.MintSessionLinkInput{UserID: f.user.ID, CredentialID: "flaky"})
	resp, _ := f.do(t, "POST", "/auth/session-link/consume", "", map[string]string{"token": tok})
	sess := cookieValue(resp)
	creds.mu.Lock()
	creds.err = errors.New("credential store down")
	creds.mu.Unlock()
	if got := f.status(t, "GET", "/auth/me", sess, nil); got != http.StatusUnauthorized {
		t.Fatalf("checker outage must fail closed; /auth/me = %d", got)
	}
}

func TestRevokeSessionsByCredentialCutsLinkedSessions(t *testing.T) {
	f, _ := newLinkFixture(t)
	ctx := context.Background()
	tok, _, _ := f.a.MintSessionLink(ctx, theauth.MintSessionLinkInput{UserID: f.user.ID, CredentialID: "tk"})
	sess, _, err := f.a.ConsumeSessionLink(ctx, tok, "ua", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.a.RevokeSessionsByCredential(ctx, "tk")
	if err != nil || n != 1 {
		t.Fatalf("RevokeSessionsByCredential = %d, %v", n, err)
	}
	if got := f.status(t, "GET", "/auth/me", sess, nil); got != http.StatusUnauthorized {
		t.Fatalf("/auth/me = %d, want 401", got)
	}
}

func TestWatchSessionCancelsOnRevoke(t *testing.T) {
	f := newSessFixture(t, nil)
	s := f.seed(t, f.user, "tok-watch", seedOpts{})
	ctx, cancel := f.a.WatchSession(context.Background(), "tok-watch", 10*time.Millisecond)
	defer cancel(nil)
	select {
	case <-ctx.Done():
		t.Fatal("cancelled while session still valid")
	case <-time.After(60 * time.Millisecond):
	}
	if err := f.a.RevokeSession(context.Background(), s.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not cancel after revoke")
	}
	if cause := context.Cause(ctx); !errors.Is(cause, theauth.ErrSessionExpired) {
		t.Fatalf("cause = %v, want ErrSessionExpired", cause)
	}
}

func TestAdminListSessionsReturnsRealRows(t *testing.T) {
	fx := newAdminFixture(t)
	path := "/admin/v1/organizations/" + fx.orgID.String() + "/sessions?user_id=" + fx.memberUser.ID.String()
	resp, body := fx.do(t, "GET", path, fx.ownerTok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var out struct {
		Sessions []struct {
			UserID string `json:"userId"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sessions) != 1 || out.Sessions[0].UserID != fx.memberUser.ID.String() {
		t.Fatalf("want exactly the member's session, got %s", body)
	}
}

func TestStepUpWithTOTP(t *testing.T) {
	srv, _ := newTOTPServer(t)
	resp, _ := postJSONWithCookies(t, srv, "/auth/email-password/signup",
		map[string]string{"email": "su-totp@h.com", "password": sessTestPassword}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("signup: %d", resp.StatusCode)
	}
	full := resp.Cookies()
	resp, body := postJSONWithCookies(t, srv, "/auth/totp/enroll/begin", struct{}{}, full)
	var enroll struct {
		Secret       string `json:"secret"`
		EnrollmentID string `json:"enrollmentId"`
	}
	if err := json.Unmarshal(body, &enroll); err != nil || resp.StatusCode != 200 {
		t.Fatalf("enroll begin: %d %s", resp.StatusCode, body)
	}
	code, _ := totp.GenerateCode(enroll.Secret, time.Now())
	if resp, body = postJSONWithCookies(t, srv, "/auth/totp/enroll/finish",
		map[string]string{"enrollmentId": enroll.EnrollmentID, "code": code}, full); resp.StatusCode != 200 {
		t.Fatalf("enroll finish: %d %s", resp.StatusCode, body)
	}
	// Enrollment finish returns no session change; full still valid.
	if resp, _ = postJSONWithCookies(t, srv, "/auth/step-up", map[string]string{"method": "totp", "code": "000000"}, full); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d, want 401", resp.StatusCode)
	}
	good, _ := totp.GenerateCode(enroll.Secret, time.Now())
	resp, body = postJSONWithCookies(t, srv, "/auth/step-up", map[string]string{"method": "totp", "code": good}, full)
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("elevatedUntil")) {
		t.Fatalf("step-up: %d %s", resp.StatusCode, body)
	}
	if resp, _ = postJSONWithCookies(t, srv, "/auth/step-up", map[string]string{"method": "totp", "code": good}, full); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed code: %d, want 401", resp.StatusCode)
	}
	for i := 0; i < 5; i++ {
		postJSONWithCookies(t, srv, "/auth/step-up", map[string]string{"method": "totp", "code": "000000"}, full)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/auth/me", nil)
	for _, c := range full {
		req.AddCookie(c)
	}
	me, _ := http.DefaultClient.Do(req)
	_ = me.Body.Close()
	if me.StatusCode != http.StatusUnauthorized {
		t.Fatalf("repeated bad codes must revoke the session; /auth/me = %d", me.StatusCode)
	}
}
