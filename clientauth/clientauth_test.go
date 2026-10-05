package clientauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/clientauth"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

type env struct {
	a    *theauth.TheAuth
	user theauth.User
	url  string
}

func newEnv(t *testing.T, dev theauth.DeviceConfig) *env {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
		APITokens: &theauth.APITokensConfig{
			UserAbilities: func(context.Context, *theauth.User) ([]string, error) { return []string{"read", "deploy"}, nil },
			Device:        &dev,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	u, err := store.CreateUser(context.Background(), theauth.User{ID: ulid.New(), Email: "a@x.test", Name: "a", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	a.Mount(r)
	r.With(a.RequireAbility("read")).Get("/api/ping", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("pong")) })
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &env{a: a, user: u, url: srv.URL}
}

func (e *env) decide(t *testing.T, userCode string, approve bool) {
	t.Helper()
	if err := e.a.DecideDeviceRequest(context.Background(), &e.user, "127.0.0.1", userCode, approve, nil); err != nil {
		t.Fatalf("decide: %v", err)
	}
}

type sleeper struct {
	mu    sync.Mutex
	calls []time.Duration
	hook  func(n int)
}

func (s *sleeper) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.calls = append(s.calls, d)
	n := len(s.calls)
	s.mu.Unlock()
	if n > 1 {
		time.Sleep(1100 * time.Millisecond)
	}
	if s.hook != nil {
		s.hook(n)
	}
	return ctx.Err()
}

func TestDeviceLogin(t *testing.T) {
	tests := []struct {
		name      string
		dev       theauth.DeviceConfig
		script    func(t *testing.T, e *env, p clientauth.DevicePrompt, n int)
		wantErr   error
		wantSleep []time.Duration
	}{
		{
			name: "approved after one pending poll",
			dev:  theauth.DeviceConfig{Interval: time.Second, DefaultAbilities: []string{"read"}},
			script: func(t *testing.T, e *env, p clientauth.DevicePrompt, n int) {
				if n == 2 {
					e.decide(t, p.UserCode, true)
				}
			},
			wantSleep: []time.Duration{time.Second, time.Second},
		},
		{
			name: "denied",
			dev:  theauth.DeviceConfig{Interval: time.Second, DefaultAbilities: []string{"read"}},
			script: func(t *testing.T, e *env, p clientauth.DevicePrompt, n int) {
				if n == 2 {
					e.decide(t, p.UserCode, false)
				}
			},
			wantErr: clientauth.ErrAccessDenied,
		},
		{
			name:    "expired on the server",
			dev:     theauth.DeviceConfig{Interval: time.Second, CodeTTL: 30 * time.Millisecond, DefaultAbilities: []string{"read"}},
			script:  func(*testing.T, *env, clientauth.DevicePrompt, int) { time.Sleep(60 * time.Millisecond) },
			wantErr: clientauth.ErrDeviceExpired,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.dev)
			store := clientauth.NewFileStoreAt(filepath.Join(t.TempDir(), "creds.json"))
			var prompt clientauth.DevicePrompt
			var opened string
			sl := &sleeper{}
			sl.hook = func(n int) { tc.script(t, e, prompt, n) }
			cred, err := clientauth.DeviceLogin(context.Background(), clientauth.DeviceOptions{
				ServerURL: e.url + "/", ClientName: "testcli", Store: store, Sleep: sl.sleep,
				Prompt:      func(p clientauth.DevicePrompt) { prompt = p },
				OpenBrowser: func(u string) error { opened = u; return nil },
			})
			if !strings.Contains(opened, "user_code=") {
				t.Fatalf("browser not opened with complete URI: %q", opened)
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if _, lerr := store.Load(context.Background(), e.url); !errors.Is(lerr, clientauth.ErrNotLoggedIn) {
					t.Fatalf("failed login must not store a credential: %v", lerr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantSleep != nil && !equalDurations(sl.calls, tc.wantSleep) {
				t.Fatalf("sleeps = %v, want %v", sl.calls, tc.wantSleep)
			}
			if cred.AccessToken == "" || cred.ExpiresAt.IsZero() || cred.Scope != "read" {
				t.Fatalf("bad credential %+v", cred)
			}
			saved, err := store.Load(context.Background(), e.url)
			if err != nil || saved.AccessToken != cred.AccessToken {
				t.Fatalf("stored credential mismatch: %+v %v", saved, err)
			}

			c, _ := clientauth.NewClient(e.url, store)
			req, _ := c.NewRequest(context.Background(), http.MethodGet, "/api/ping", nil)
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("ping status %d", resp.StatusCode)
			}
		})
	}
}

func equalDurations(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDeviceLoginContextCancel(t *testing.T) {
	e := newEnv(t, theauth.DeviceConfig{Interval: time.Second, DefaultAbilities: []string{"read"}})
	ctx, cancel := context.WithCancel(context.Background())
	_, err := clientauth.DeviceLogin(ctx, clientauth.DeviceOptions{
		ServerURL: e.url, Out: &strings.Builder{},
		Sleep: func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestClientRealServerRevokedAndExpired(t *testing.T) {
	e := newEnv(t, theauth.DeviceConfig{Interval: time.Second, DefaultAbilities: []string{"read"}})
	store := clientauth.NewFileStoreAt(filepath.Join(t.TempDir(), "creds.json"))
	sl := &sleeper{}
	var prompt clientauth.DevicePrompt
	sl.hook = func(int) { e.decide(t, prompt.UserCode, true) }
	cred, err := clientauth.DeviceLogin(context.Background(), clientauth.DeviceOptions{
		ServerURL: e.url, Store: store, Sleep: sl.sleep, Out: &strings.Builder{},
		Prompt: func(p clientauth.DevicePrompt) { prompt = p },
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("server rejects an unknown token", func(t *testing.T) {
		bad := cred
		bad.AccessToken = "tk_bogus"
		_ = store.Save(context.Background(), bad)
		c, _ := clientauth.NewClient(e.url, store)
		req, _ := c.NewRequest(context.Background(), http.MethodGet, "/api/ping", nil)
		if _, err := c.Do(req); !errors.Is(err, clientauth.ErrReloginRequired) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("locally expired never hits the network", func(t *testing.T) {
		_ = store.Save(context.Background(), cred)
		c, _ := clientauth.NewClient(e.url, store)
		c.Now = func() time.Time { return cred.ExpiresAt.Add(time.Second) }
		req, _ := c.NewRequest(context.Background(), http.MethodGet, "/api/ping", nil)
		if _, err := c.Do(req); !errors.Is(err, clientauth.ErrReloginRequired) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("not logged in", func(t *testing.T) {
		empty := clientauth.NewFileStoreAt(filepath.Join(t.TempDir(), "x.json"))
		c, _ := clientauth.NewClient(e.url, empty)
		req, _ := c.NewRequest(context.Background(), http.MethodGet, "/api/ping", nil)
		if _, err := c.Do(req); !errors.Is(err, clientauth.ErrNotLoggedIn) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("refuses a foreign origin", func(t *testing.T) {
		_ = store.Save(context.Background(), cred)
		c, _ := clientauth.NewClient(e.url, store)
		req, _ := http.NewRequest(http.MethodGet, "http://example.invalid/x", nil)
		if _, err := c.Do(req); err == nil || errors.Is(err, clientauth.ErrReloginRequired) {
			t.Fatalf("err = %v", err)
		}
	})
}

func selfServer(t *testing.T, revokeStatus int) (*httptest.Server, *int) {
	t.Helper()
	revoked := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/tokens/current", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tk_good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodDelete {
			revoked++
			w.WriteHeader(revokeStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "01X", "name": "device: cli", "abilities": []string{"read"}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &revoked
}

func (e *env) login(t *testing.T) (*clientauth.Client, clientauth.TokenStore) {
	t.Helper()
	store := clientauth.NewFileStoreAt(filepath.Join(t.TempDir(), "creds.json"))
	sl := &sleeper{}
	var prompt clientauth.DevicePrompt
	sl.hook = func(int) { e.decide(t, prompt.UserCode, true) }
	if _, err := clientauth.DeviceLogin(context.Background(), clientauth.DeviceOptions{
		ServerURL: e.url, ClientName: "testcli", Store: store, Sleep: sl.sleep, Out: &strings.Builder{},
		Prompt: func(p clientauth.DevicePrompt) { prompt = p },
	}); err != nil {
		t.Fatal(err)
	}
	c, err := clientauth.NewClient(e.url, store)
	if err != nil {
		t.Fatal(err)
	}
	return c, store
}

func TestWhoamiAndLogoutAgainstRealServer(t *testing.T) {
	ctx := context.Background()
	dev := theauth.DeviceConfig{Interval: time.Second, DefaultAbilities: []string{"read"}}

	t.Run("whoami returns the token metadata", func(t *testing.T) {
		e := newEnv(t, dev)
		c, _ := e.login(t)
		id, err := c.Whoami(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if id.ID == "" || id.OwnerID != e.user.ID.String() || id.OwnerKind != theauth.OwnerKindUser ||
			id.Kind != theauth.APITokenKindPersonal || len(id.Abilities) != 1 || id.Abilities[0] != "read" ||
			id.ExpiresAt == nil || id.CreatedAt.IsZero() || !strings.Contains(id.Name, "testcli") {
			t.Fatalf("whoami: %+v", id)
		}
	})
	t.Run("logout revokes server side", func(t *testing.T) {
		e := newEnv(t, dev)
		c, store := e.login(t)
		cred, err := store.Load(ctx, e.url)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Logout(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(ctx, e.url); !errors.Is(err, clientauth.ErrNotLoggedIn) {
			t.Fatalf("credential should be gone: %v", err)
		}
		if _, err := e.a.AuthenticateAPIToken(ctx, cred.AccessToken); !errors.Is(err, theauth.ErrAPITokenInvalid) {
			t.Fatalf("token still valid after logout: %v", err)
		}
		_ = store.Save(ctx, cred)
		if _, err := c.Whoami(ctx); !errors.Is(err, clientauth.ErrReloginRequired) {
			t.Fatalf("whoami after revoke = %v, want ErrReloginRequired", err)
		}
		if err := c.Logout(ctx); err != nil {
			t.Fatalf("logout with an already revoked token must still succeed: %v", err)
		}
	})
	t.Run("custom SelfPath", func(t *testing.T) {
		e := newEnv(t, dev)
		c, _ := e.login(t)
		c.SelfPath = "/tokens/nope"
		if _, err := c.Whoami(ctx); err == nil || errors.Is(err, clientauth.ErrReloginRequired) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestWhoamiAndLogoutAgainstStub(t *testing.T) {
	ctx := context.Background()
	t.Run("whoami", func(t *testing.T) {
		srv, _ := selfServer(t, http.StatusNoContent)
		store := clientauth.NewFileStoreAt(filepath.Join(t.TempDir(), "c.json"))
		_ = store.Save(ctx, clientauth.Credential{ServerURL: srv.URL, AccessToken: "tk_good"})
		c, _ := clientauth.NewClient(srv.URL, store)
		id, err := c.Whoami(ctx)
		if err != nil || id.Name != "device: cli" || len(id.Abilities) != 1 {
			t.Fatalf("whoami: %+v %v", id, err)
		}
	})
	t.Run("logout revokes then deletes", func(t *testing.T) {
		srv, revoked := selfServer(t, http.StatusNoContent)
		store := clientauth.NewFileStoreAt(filepath.Join(t.TempDir(), "c.json"))
		_ = store.Save(ctx, clientauth.Credential{ServerURL: srv.URL, AccessToken: "tk_good"})
		c, _ := clientauth.NewClient(srv.URL, store)
		if err := c.Logout(ctx); err != nil || *revoked != 1 {
			t.Fatalf("logout: %v revoked=%d", err, *revoked)
		}
		if _, err := store.Load(ctx, srv.URL); !errors.Is(err, clientauth.ErrNotLoggedIn) {
			t.Fatalf("credential should be gone: %v", err)
		}
	})
	t.Run("logout with a dead token still clears local state", func(t *testing.T) {
		srv, _ := selfServer(t, http.StatusNoContent)
		store := clientauth.NewFileStoreAt(filepath.Join(t.TempDir(), "c.json"))
		_ = store.Save(ctx, clientauth.Credential{ServerURL: srv.URL, AccessToken: "tk_dead"})
		c, _ := clientauth.NewClient(srv.URL, store)
		if err := c.Logout(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(ctx, srv.URL); !errors.Is(err, clientauth.ErrNotLoggedIn) {
			t.Fatalf("credential should be gone: %v", err)
		}
	})
	t.Run("logout surfaces a server failure but still deletes", func(t *testing.T) {
		srv, _ := selfServer(t, http.StatusInternalServerError)
		store := clientauth.NewFileStoreAt(filepath.Join(t.TempDir(), "c.json"))
		_ = store.Save(ctx, clientauth.Credential{ServerURL: srv.URL, AccessToken: "tk_good"})
		c, _ := clientauth.NewClient(srv.URL, store)
		var se *clientauth.ServerError
		if err := c.Logout(ctx); !errors.As(err, &se) || se.Status != 500 {
			t.Fatalf("err = %v", err)
		}
		if _, err := store.Load(ctx, srv.URL); !errors.Is(err, clientauth.ErrNotLoggedIn) {
			t.Fatalf("credential should be gone: %v", err)
		}
	})
}

func TestFileStore(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "app")
	path := filepath.Join(dir, "credentials.json")
	s := clientauth.NewFileStoreAt(path)

	if _, err := s.Load(ctx, "https://a.test"); !errors.Is(err, clientauth.ErrNotLoggedIn) {
		t.Fatalf("empty store: %v", err)
	}
	for _, c := range []clientauth.Credential{
		{ServerURL: "https://A.test/", AccessToken: "one"},
		{ServerURL: "https://b.test", AccessToken: "two"},
	} {
		if err := s.Save(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Load(ctx, "https://a.test")
	if err != nil || got.AccessToken != "one" {
		t.Fatalf("normalized lookup: %+v %v", got, err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		di, _ := os.Stat(dir)
		if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
			t.Fatalf("modes: file %v dir %v", fi.Mode().Perm(), di.Mode().Perm())
		}
	}
	if err := s.Delete(ctx, "https://a.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, "https://a.test"); !errors.Is(err, clientauth.ErrNotLoggedIn) {
		t.Fatal("a.test should be deleted")
	}
	if got, _ := s.Load(ctx, "https://b.test"); got.AccessToken != "two" {
		t.Fatal("b.test must survive deleting a.test")
	}
	if err := s.Delete(ctx, "https://nope.test"); err != nil {
		t.Fatalf("delete of unknown server: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("stray temp or lock files left: %v", entries)
	}
}

func TestFileStoreConcurrentWritersLoseNothing(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "creds.json")
	const n = 24
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := clientauth.NewFileStoreAt(path)
			srv := "https://s" + string(rune('a'+i)) + ".test"
			if err := s.Save(ctx, clientauth.Credential{ServerURL: srv, AccessToken: srv}); err != nil {
				t.Errorf("save %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	s := clientauth.NewFileStoreAt(path)
	for i := range n {
		srv := "https://s" + string(rune('a'+i)) + ".test"
		if c, err := s.Load(ctx, srv); err != nil || c.AccessToken != srv {
			t.Fatalf("lost write for %s: %+v %v", srv, c, err)
		}
	}
}

type fakeKeychain struct {
	mu sync.Mutex
	m  map[string]string
}

func (k *fakeKeychain) Get(service, user string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[service+"|"+user]
	if !ok {
		return "", clientauth.ErrKeychainNotFound
	}
	return v, nil
}

func (k *fakeKeychain) Set(service, user, secret string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[service+"|"+user] = secret
	return nil
}

func (k *fakeKeychain) Delete(service, user string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.m[service+"|"+user]; !ok {
		return clientauth.ErrKeychainNotFound
	}
	delete(k.m, service+"|"+user)
	return nil
}

func TestKeychainStore(t *testing.T) {
	ctx := context.Background()
	s := clientauth.NewKeychainStore("mycli", &fakeKeychain{m: map[string]string{}})
	if _, err := s.Load(ctx, "https://a.test"); !errors.Is(err, clientauth.ErrNotLoggedIn) {
		t.Fatalf("empty: %v", err)
	}
	if err := s.Save(ctx, clientauth.Credential{ServerURL: "https://a.test/", AccessToken: "t"}); err != nil {
		t.Fatal(err)
	}
	if c, err := s.Load(ctx, "https://a.test"); err != nil || c.AccessToken != "t" {
		t.Fatalf("load: %+v %v", c, err)
	}
	if err := s.Delete(ctx, "https://a.test"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "https://a.test"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

func TestNormalizeServerURL(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://App.Example.com/", "https://app.example.com"},
		{"http://localhost:8080/base/", "http://localhost:8080/base"},
		{"https://x.test?q=1#f", "https://x.test"},
		{"ftp://x.test", ""},
		{"not a url", ""},
	}
	for _, tc := range tests {
		got, err := clientauth.NormalizeServerURL(tc.in)
		if (err != nil) != (tc.want == "") || got != tc.want {
			t.Errorf("%q: got %q err %v, want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestDeviceLoginPollBackoff(t *testing.T) {
	ok := `{"access_token":"tk_x","token_type":"Bearer","expires_in":3600,"scope":"read"}`
	tests := []struct {
		name      string
		script    []string
		wantSleep []time.Duration
		wantErr   error
	}{
		{"slow_down adds five seconds each time", []string{"slow_down", "slow_down", "pending", "ok"},
			[]time.Duration{2 * time.Second, 7 * time.Second, 12 * time.Second, 12 * time.Second}, nil},
		{"http 429 is treated as slow_down", []string{"429", "ok"},
			[]time.Duration{2 * time.Second, 7 * time.Second}, nil},
		{"denied after pending", []string{"pending", "access_denied"},
			[]time.Duration{2 * time.Second, 2 * time.Second}, clientauth.ErrAccessDenied},
		{"expired_token", []string{"expired_token"}, []time.Duration{2 * time.Second}, clientauth.ErrDeviceExpired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			polls := 0
			mux := http.NewServeMux()
			mux.HandleFunc("/auth/device/code", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"device_code":"d","user_code":"AAAA-BBBB","verification_uri":"http://x/device","expires_in":600,"interval":2}`))
			})
			mux.HandleFunc("/auth/device/token", func(w http.ResponseWriter, _ *http.Request) {
				mu.Lock()
				step := tc.script[polls]
				polls++
				mu.Unlock()
				switch step {
				case "ok":
					_, _ = w.Write([]byte(ok))
				case "429":
					w.WriteHeader(http.StatusTooManyRequests)
				default:
					code := step
					if step == "pending" {
						code = "authorization_pending"
					}
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
				}
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			sl := &sleeper2{}
			_, err := clientauth.DeviceLogin(context.Background(), clientauth.DeviceOptions{
				ServerURL: srv.URL, Out: &strings.Builder{}, Sleep: sl.sleep,
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if !equalDurations(sl.calls, tc.wantSleep) {
				t.Fatalf("sleeps = %v, want %v", sl.calls, tc.wantSleep)
			}
		})
	}
}

type sleeper2 struct{ calls []time.Duration }

func (s *sleeper2) sleep(_ context.Context, d time.Duration) error {
	s.calls = append(s.calls, d)
	return nil
}
