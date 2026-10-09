package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

// fakeAS is a scripted token endpoint for the polling-rule tests.
type fakeAS struct {
	mu       sync.Mutex
	replies  []string
	polls    int
	srv      *httptest.Server
	interval int
}

func newFakeAS(t *testing.T, interval int, replies ...string) *fakeAS {
	t.Helper()
	f := &fakeAS{replies: replies, interval: interval}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint":                f.srv.URL + "/token",
			"device_authorization_endpoint": f.srv.URL + "/device",
		})
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dc", "user_code": "ABCD-EFGH", "verification_uri": f.srv.URL + "/v",
			"verification_uri_complete": f.srv.URL + "/v?user_code=ABCD-EFGH", "expires_in": 600, "interval": f.interval,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		reply := f.replies[min(f.polls, len(f.replies)-1)]
		f.polls++
		if reply == "ok" {
			_, _ = w.Write([]byte(`{"access_token":"AT","token_type":"Bearer","expires_in":3600}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"` + reply + `"}`))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func TestPollingRules(t *testing.T) {
	cases := []struct {
		name      string
		interval  int
		replies   []string
		wantErr   string
		wantSleep []time.Duration
	}{
		{"pending then ok", 5, []string{"authorization_pending", "authorization_pending", "ok"}, "", []time.Duration{5 * time.Second, 5 * time.Second, 5 * time.Second}},
		{"slow_down adds five seconds", 5, []string{"slow_down", "authorization_pending", "ok"}, "", []time.Duration{5 * time.Second, 10 * time.Second, 10 * time.Second}},
		{"server interval is honored", 2, []string{"ok"}, "", []time.Duration{2 * time.Second}},
		{"denied", 5, []string{"access_denied"}, "denied", []time.Duration{5 * time.Second}},
		{"expired", 5, []string{"expired_token"}, "expired", []time.Duration{5 * time.Second}},
		{"other errors surface", 5, []string{"invalid_grant"}, "invalid_grant", []time.Duration{5 * time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			as := newFakeAS(t, tc.interval, tc.replies...)
			var slept []time.Duration
			var out bytes.Buffer
			f := &flow{HTTP: http.DefaultClient, Out: &out, Sleep: func(_ context.Context, d time.Duration) error {
				slept = append(slept, d)
				return nil
			}}
			tok, err := f.Login(context.Background(), config{Issuer: as.srv.URL, ClientID: "c"})
			if tc.wantErr == "" {
				if err != nil || tok.AccessToken != "AT" {
					t.Fatalf("tok=%+v err=%v", tok, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
			if len(slept) != len(tc.wantSleep) {
				t.Fatalf("sleeps %v, want %v", slept, tc.wantSleep)
			}
			for i := range slept {
				if slept[i] != tc.wantSleep[i] {
					t.Fatalf("sleeps %v, want %v", slept, tc.wantSleep)
				}
			}
			if !strings.Contains(out.String(), "ABCD-EFGH") {
				t.Fatalf("user code not shown:\n%s", out.String())
			}
		})
	}

	t.Run("cancelling stops the loop", func(t *testing.T) {
		as := newFakeAS(t, 5, "authorization_pending")
		ctx, cancel := context.WithCancel(context.Background())
		f := &flow{HTTP: http.DefaultClient, Out: io.Discard, Sleep: func(ctx context.Context, _ time.Duration) error {
			cancel()
			return ctx.Err()
		}}
		if _, err := f.Login(ctx, config{Issuer: as.srv.URL, ClientID: "c"}); err == nil {
			t.Fatal("expected a cancellation error")
		}
	})
}

// TestLoginAgainstRealAS drives the CLI against the library's own AS: the
// "user" approves through the verification JSON API between polls.
func TestLoginAgainstRealAS(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	store := memory.New()
	var base string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { chiRouter.ServeHTTP(w, r) })
	srv := httptest.NewServer(handler)
	defer srv.Close()
	base = srv.URL
	auth, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: base, EncryptionKey: key, SuppressTrustedProxiesWarning: true,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer: base, DisableRotation: true, RegistrationTokens: []string{"reg"},
			Resources:           []theauth.ProtectedResource{{Identifier: base + "/api", Scopes: []string{"profile"}}},
			DeviceAuthorization: &theauth.DeviceAuthorizationConfig{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	r := chi.NewRouter()
	auth.Mount(r)
	chiRouter = r

	user := theauth.User{ID: ulid.New(), Email: "u@example.com"}
	_, _ = store.CreateUser(context.Background(), user)
	raw, _ := crypto.NewToken()
	_, _ = store.CreateSession(context.Background(), theauth.Session{ID: ulid.New(), UserID: user.ID,
		TokenHash: crypto.HashToken(raw), AuthLevel: theauth.AuthLevelFull, ExpiresAt: time.Now().Add(time.Hour)})

	reg, _ := http.NewRequest(http.MethodPost, base+"/oauth/register",
		strings.NewReader(`{"token_endpoint_auth_method":"none","grant_types":["urn:ietf:params:oauth:grant-type:device_code"]}`))
	reg.Header.Set("Authorization", "Bearer reg")
	reg.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(reg)
	if err != nil {
		t.Fatal(err)
	}
	var client struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&client)
	_ = resp.Body.Close()

	var out bytes.Buffer
	codeRe := regexp.MustCompile(`code: ([A-Z-]+)`)
	approved := false
	f := &flow{HTTP: http.DefaultClient, Out: &out, Sleep: func(context.Context, time.Duration) error {
		// Called before every poll. Approve the first time, as a user would
		// while the CLI waits; the injected sleep returns at once.
		if approved {
			return nil
		}
		m := codeRe.FindStringSubmatch(out.String())
		if m == nil {
			t.Fatalf("no user code printed yet:\n%s", out.String())
		}
		body, _ := json.Marshal(map[string]string{"user_code": m[1], "action": "approve"})
		req, _ := http.NewRequest(http.MethodPost, base+"/oauth/device", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "theauth_session", Value: raw})
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("approve failed: %v %v", err, resp)
		}
		_ = resp.Body.Close()
		approved = true
		return nil
	}}
	tok, err := f.Login(context.Background(), config{Issuer: base, ClientID: client.ClientID, Scope: "profile", Resource: base + "/api"})
	if err != nil {
		t.Fatalf("Login: %v\n%s", err, out.String())
	}
	if tok.AccessToken == "" || tok.TokenType != "Bearer" || tok.Scope != "profile" {
		t.Fatalf("tokens: %+v", tok)
	}
}

var chiRouter http.Handler = http.NotFoundHandler()
