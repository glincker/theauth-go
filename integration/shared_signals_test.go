package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/integration/internal/testutil"
	"github.com/glincker/theauth-go/v2/signals"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

const ssIssuer = "https://auth.example.com"

func ssAuth(t *testing.T, ss *theauth.SharedSignalsConfig) (*theauth.TheAuth, *httptest.Server) {
	t.Helper()
	a, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", EncryptionKey: bytes.Repeat([]byte{9}, 32),
		AccountState:   true,
		RateLimitPerIP: 10000, RateLimitPerEmail: 10000,
		LoginThrottle: &theauth.LoginThrottleConfig{Disabled: true},
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer: ssIssuer, DisableRotation: true,
			Resources: []theauth.ProtectedResource{{Identifier: "https://api.example.com", Scopes: []string{"read"}}},
		},
		SharedSignals: ss,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	r := chi.NewRouter()
	a.Mount(r)
	if h := a.SharedSignalsHandler(); h != nil {
		r.Handle("/ssf/*", h)
		r.Handle("/.well-known/ssf-configuration", h)
	}
	if h := a.SharedSignalsReceiverHandler(); h != nil {
		r.Handle("/ssf-receive", h)
	}
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return a, srv
}

func ssCall(t *testing.T, srv *httptest.Server, method, path, tok string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, raw)
	}
	return out
}

func ssPoll(t *testing.T, srv *httptest.Server, streamID string, ack []string) map[string]string {
	t.Helper()
	out := ssCall(t, srv, "POST", "/ssf/poll/"+streamID, "ssf-token", map[string]any{"returnImmediately": true, "ack": ack})
	sets := map[string]string{}
	for jti, tok := range out["sets"].(map[string]any) {
		sets[jti] = tok.(string)
	}
	return sets
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestSharedSignalsEmitsFromAuditEvents(t *testing.T) {
	a, srv := ssAuth(t, &theauth.SharedSignalsConfig{
		Authenticate:  signals.StaticBearerAuth(map[string]string{"ssf-token": "rp-1"}),
		EmitFromAudit: true,
	})
	meta := ssCall(t, srv, "GET", "/.well-known/ssf-configuration", "", nil)
	if meta["issuer"] != ssIssuer || meta["jwks_uri"] != ssIssuer+"/oauth/jwks" {
		t.Fatalf("metadata: %v", meta)
	}
	stream := ssCall(t, srv, "POST", "/ssf/stream", "ssf-token", map[string]any{
		"delivery": map[string]any{"method": signals.MethodPoll},
	})
	sid := stream["stream_id"].(string)

	ctx := context.Background()
	u, _, err := testutil.SignupWithPasswordForTest(a, ctx, "ss@example.com", "correct-horse-battery-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RevokeUserSessions(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.DisableUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}

	// Verify through the real receiver path: JWKS served by the AS itself.
	var mu sync.Mutex
	got := map[string]signals.Event{}
	rx, err := signals.NewReceiver(signals.ReceiverConfig{
		Audience: "rp-1", Issuers: map[string]string{ssIssuer: srv.URL + "/oauth/jwks"},
		AllowPrivateNetworks: true, AllowInsecureHTTP: true,
		Handlers: []signals.Handler{signals.HandlerFunc(func(_ context.Context, _ *signals.SET, ev signals.Event) error {
			mu.Lock()
			got[ev.Type] = ev
			mu.Unlock()
			return nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	var acks []string
	waitFor(t, "sessions-revoked and account-disabled", func() bool {
		for jti, tok := range ssPoll(t, srv, sid, acks) {
			if _, err := rx.Handle(ctx, tok); err != nil {
				t.Fatalf("SET did not verify against AS JWKS: %v", err)
			}
			acks = append(acks, jti)
		}
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 2
	})
	mu.Lock()
	defer mu.Unlock()
	for _, typ := range []string{signals.EventSessionsRevoked, signals.EventAccountDisabled} {
		ev, ok := got[typ]
		if !ok {
			t.Fatalf("missing %s in %v", typ, got)
		}
		if ev.Subject.Format != signals.FormatIssSub || ev.Subject.Iss != ssIssuer || ev.Subject.Sub != u.ID.String() {
			t.Fatalf("%s subject: %+v", typ, ev.Subject)
		}
	}
}

func TestSharedSignalsEmissionIsOptIn(t *testing.T) {
	a, srv := ssAuth(t, &theauth.SharedSignalsConfig{
		Authenticate: signals.StaticBearerAuth(map[string]string{"ssf-token": "rp-1"}),
	})
	stream := ssCall(t, srv, "POST", "/ssf/stream", "ssf-token", map[string]any{"delivery": map[string]any{"method": signals.MethodPoll}})
	ctx := context.Background()
	u, _, _ := testutil.SignupWithPasswordForTest(a, ctx, "optin@example.com", "correct-horse-battery-1")
	_ = a.RevokeUserSessions(ctx, u.ID)
	time.Sleep(150 * time.Millisecond)
	if sets := ssPoll(t, srv, stream["stream_id"].(string), nil); len(sets) != 0 {
		t.Fatalf("EmitFromAudit is off but %d SETs were queued", len(sets))
	}
	// Custom events still go out through the transmitter API.
	if err := a.SharedSignalsTransmitter().Emit(ctx, signals.NewDeviceComplianceChange(signals.IssSub(ssIssuer, u.ID.String()), time.Now(), "compliant", "not-compliant")); err != nil {
		t.Fatal(err)
	}
	if sets := ssPoll(t, srv, stream["stream_id"].(string), nil); len(sets) != 1 {
		t.Fatalf("custom emit: %d", len(sets))
	}
}

func TestSharedSignalsRequiresAuthorizationServer(t *testing.T) {
	_, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", EncryptionKey: bytes.Repeat([]byte{9}, 32),
		SharedSignals: &theauth.SharedSignalsConfig{Authenticate: func(*http.Request) (string, bool) { return "", false }},
	})
	if err == nil {
		t.Fatal("SharedSignals without AuthorizationServer must fail fast")
	}
}

func TestSharedSignalsReceiverRevokesLocalSessions(t *testing.T) {
	// A peer transmitter: its own key, JWKS and metadata served over HTTP.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var peerURL string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": peerURL, "jwks_uri": peerURL + "/jwks",
			"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "kid": "peer-1", "alg": "EdDSA", "use": "sig",
				"x": base64.RawURLEncoding.EncodeToString(pub)}},
		})
	}))
	defer peer.Close()
	peerURL = peer.URL
	signer := signals.NewKeySigner("peer-1", "EdDSA", priv)

	a, srv := ssAuth(t, &theauth.SharedSignalsConfig{
		Authenticate: signals.StaticBearerAuth(map[string]string{"ssf-token": "rp-1"}),
		Receiver: &theauth.SharedSignalsReceiverConfig{
			Audience: "https://auth.example.com/ssf-receive", Issuers: map[string]string{peerURL: ""},
			AllowPrivateNetworks: true, AllowInsecureHTTP: true,
			Authenticate: func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer peer-secret" },
		},
	})
	ctx := context.Background()
	alice, _, err := testutil.SignupWithPasswordForTest(a, ctx, "alice@example.com", "correct-horse-battery-1")
	if err != nil {
		t.Fatal(err)
	}
	bob, _, _ := testutil.SignupWithPasswordForTest(a, ctx, "bob@example.com", "correct-horse-battery-1")
	aliceTok, _, err := testutil.SigninWithPasswordForTest(a, ctx, "alice@example.com", "correct-horse-battery-1", "ua", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	bobTok, _, _ := testutil.SigninWithPasswordForTest(a, ctx, "bob@example.com", "correct-horse-battery-1", "ua", "10.0.0.1")
	_ = alice
	_ = bob

	push := func(set *signals.SET) int {
		tok, err := set.Sign(signer)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("POST", srv.URL+"/ssf-receive", strings.NewReader(tok))
		req.Header.Set("Content-Type", "application/secevent+jwt")
		req.Header.Set("Authorization", "Bearer peer-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	mk := func(ev signals.Event) *signals.SET {
		return &signals.SET{Issuer: peerURL, Audience: []string{"https://auth.example.com/ssf-receive"},
			IssuedAt: time.Now(), JTI: strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", ""), Events: []signals.Event{ev}}
	}
	// credential-change must not revoke
	if c := push(mk(signals.NewCredentialChange(signals.EmailSubject("alice@example.com"), time.Now(), "password", "update"))); c != 202 {
		t.Fatalf("credential-change: %d", c)
	}
	if _, _, err := testutil.ValidateSessionForTest(a, ctx, aliceTok); err != nil {
		t.Fatalf("alice must still be signed in: %v", err)
	}
	// session-revoked for alice's email revokes alice only
	if c := push(mk(signals.NewSessionRevoked(signals.EmailSubject("Alice@Example.com"), time.Now(), "", ""))); c != 202 {
		t.Fatalf("session-revoked: %d", c)
	}
	if _, _, err := testutil.ValidateSessionForTest(a, ctx, aliceTok); err == nil {
		t.Fatal("alice's session must be revoked")
	}
	if _, _, err := testutil.ValidateSessionForTest(a, ctx, bobTok); err != nil {
		t.Fatalf("bob must be untouched: %v", err)
	}
	// account-disabled for bob (complex subject) revokes bob
	cs := signals.ComplexSubject(map[string]signals.Subject{"user": signals.EmailSubject("bob@example.com")})
	if c := push(mk(signals.NewAccountDisabled(cs, "hijacking"))); c != 202 {
		t.Fatalf("account-disabled: %d", c)
	}
	if _, _, err := testutil.ValidateSessionForTest(a, ctx, bobTok); err == nil {
		t.Fatal("bob's session must be revoked")
	}
	// unknown user is acknowledged and ignored
	if c := push(mk(signals.NewSessionsRevoked(signals.EmailSubject("nobody@example.com")))); c != 202 {
		t.Fatalf("unknown user: %d", c)
	}
}
