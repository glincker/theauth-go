package clientauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/clientauth"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

func TestDeviceLoginWithCustomPathPrefix(t *testing.T) {
	const prefix = "/api/v1/auth"
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", PathPrefix: prefix, SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
		APITokens: &theauth.APITokensConfig{
			UserAbilities: func(context.Context, *theauth.User) ([]string, error) { return []string{"read"}, nil },
			Device:        &theauth.DeviceConfig{Interval: time.Second, DefaultAbilities: []string{"read"}},
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

	var prompt clientauth.DevicePrompt
	sl := &sleeper{hook: func(int) {
		if err := a.DecideDeviceRequest(context.Background(), &u, "127.0.0.1", prompt.UserCode, true, nil); err != nil {
			t.Errorf("decide: %v", err)
		}
	}}
	creds := clientauth.NewFileStoreAt(filepath.Join(t.TempDir(), "creds.json"))
	cred, err := clientauth.DeviceLogin(context.Background(), clientauth.DeviceOptions{
		ServerURL: srv.URL, AuthPath: prefix, Store: creds, Sleep: sl.sleep, Out: &strings.Builder{},
		Prompt: func(p clientauth.DevicePrompt) { prompt = p },
	})
	if err != nil {
		t.Fatalf("device login: %v", err)
	}
	if cred.AccessToken == "" {
		t.Fatal("no access token")
	}

	c, err := clientauth.NewClient(srv.URL, creds)
	if err != nil {
		t.Fatal(err)
	}
	c.AuthPath = prefix
	req, _ := c.NewRequest(context.Background(), http.MethodGet, "/api/ping", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ping with minted token: %d", resp.StatusCode)
	}

	self, _ := http.NewRequest(http.MethodGet, srv.URL+prefix+"/tokens/current", nil)
	self.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	sr, err := http.DefaultClient.Do(self)
	if err != nil {
		t.Fatal(err)
	}
	_ = sr.Body.Close()
	if sr.StatusCode != http.StatusOK {
		t.Fatalf("token route under prefix: %d", sr.StatusCode)
	}
}
