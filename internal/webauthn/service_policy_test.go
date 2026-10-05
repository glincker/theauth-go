package webauthn_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

type recorder struct {
	mu sync.Mutex
	ev []theauth.AuthEvent
}

func (r *recorder) sink(_ context.Context, e theauth.AuthEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ev = append(r.ev, e)
}

func (r *recorder) count(typ theauth.AuthEventType) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.ev {
		if e.Type == typ {
			n++
		}
	}
	return n
}

func newPolicyAuth(t *testing.T, wa theauth.WebAuthnConfig) (*theauth.TheAuth, *memory.Store, *recorder) {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	rec := &recorder{}
	store := memory.New()
	wa.RPID, wa.RPDisplayName, wa.RPOrigins = testRPID, "Example", []string{testOrigin}
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "http://localhost", EncryptionKey: key,
		WebAuthn: &wa, AuthEventSink: rec.sink,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, store, rec
}

func register(t *testing.T, a *theauth.TheAuth, uid theauth.ULID, va *virtualAuthenticator) (theauth.WebAuthnCredential, error) {
	t.Helper()
	chal, tok := beginRegistrationChallenge(t, a, uid)
	return a.FinishPasskeyRegistration(context.Background(), uid, tok, "key", bytes.NewReader(va.registrationBody(t, chal, false, false)))
}

func login(t *testing.T, a *theauth.TheAuth, uid theauth.ULID, va *virtualAuthenticator) error {
	t.Helper()
	chal, tok := beginLoginChallenge(t, a)
	_, _, err := a.FinishPasskeyLogin(context.Background(), tok, bytes.NewReader(va.assertionBody(t, chal, uid[:], false, false)), "ua", "198.51.100.9")
	return err
}

func TestRequireUserVerification(t *testing.T) {
	ctx := context.Background()
	a, store, _ := newPolicyAuth(t, theauth.WebAuthnConfig{RequireUserVerification: true})
	u, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "uv@example.com"})

	creation, _, err := a.BeginPasskeyRegistration(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if creation.Response.AuthenticatorSelection.UserVerification != "required" {
		t.Fatalf("registration UV = %q, want required", creation.Response.AuthenticatorSelection.UserVerification)
	}
	assertion, _, err := a.BeginPasskeyLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if assertion.Response.UserVerification != "required" {
		t.Fatalf("login UV = %q, want required", assertion.Response.UserVerification)
	}

	noUV := newVirtualAuthenticator(t)
	noUV.noUV = true
	if _, err := register(t, a, u.ID, noUV); err == nil {
		t.Fatal("registration without UV must be rejected")
	}

	va := newVirtualAuthenticator(t)
	if _, err := register(t, a, u.ID, va); err != nil {
		t.Fatalf("registration with UV: %v", err)
	}
	va.noUV = true
	if err := login(t, a, u.ID, va); err == nil {
		t.Fatal("login without UV must be rejected")
	}
	va.noUV = false
	if err := login(t, a, u.ID, va); err != nil {
		t.Fatalf("login with UV: %v", err)
	}
}

func TestUserVerificationNotRequiredByDefault(t *testing.T) {
	ctx := context.Background()
	a, store, _ := newPolicyAuth(t, theauth.WebAuthnConfig{})
	u, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "nouv@example.com"})
	va := newVirtualAuthenticator(t)
	va.noUV = true
	if _, err := register(t, a, u.ID, va); err != nil {
		t.Fatalf("default config must accept non-UV registration: %v", err)
	}
	if err := login(t, a, u.ID, va); err != nil {
		t.Fatalf("default config must accept non-UV login: %v", err)
	}
}

func TestCloneWarningPolicy(t *testing.T) {
	cases := []struct {
		name      string
		policy    theauth.CloneWarningPolicy
		wantLogin bool
	}{
		{"default rejects", "", false},
		{"explicit reject", theauth.CloneWarningReject, false},
		{"flag allows and records", theauth.CloneWarningFlag, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			a, store, rec := newPolicyAuth(t, theauth.WebAuthnConfig{CloneWarning: c.policy})
			u, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "clone@example.com"})
			va := newVirtualAuthenticator(t)
			if _, err := register(t, a, u.ID, va); err != nil {
				t.Fatal(err)
			}
			if err := login(t, a, u.ID, va); err != nil {
				t.Fatalf("first login: %v", err)
			}
			va.freezeCount = true
			err := login(t, a, u.ID, va)
			if c.wantLogin && err != nil {
				t.Fatalf("flag policy must allow the login: %v", err)
			}
			if !c.wantLogin && !errors.Is(err, theauth.ErrReplayDetected) {
				t.Fatalf("want ErrReplayDetected, got %v", err)
			}
			if rec.count(theauth.AuthEventPasskeyCloneWarning) != 1 {
				t.Fatalf("clone warning event count = %d, want 1", rec.count(theauth.AuthEventPasskeyCloneWarning))
			}
			wantFail := 0
			if !c.wantLogin {
				wantFail = 1
			}
			if rec.count(theauth.AuthEventLoginFailure) != wantFail {
				t.Fatalf("login failure events = %d, want %d", rec.count(theauth.AuthEventLoginFailure), wantFail)
			}
		})
	}
}

func TestRPIDComesFromConfigNotHost(t *testing.T) {
	a, _, _ := newPolicyAuth(t, theauth.WebAuthnConfig{})
	r := chi.NewRouter()
	a.Mount(r)
	for _, host := range []string{"evil.example.net", "localhost:8080", "203.0.113.5"} {
		req := httptest.NewRequest(http.MethodPost, "/auth/webauthn/login/begin", nil)
		req.Host = host
		req.Header.Set("X-Forwarded-Host", host)
		req.Header.Set("X-Forwarded-Proto", "http")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("host %s: %d %s", host, rec.Code, rec.Body)
		}
		var out struct {
			PublicKey struct {
				RPID string `json:"rpId"`
			} `json:"publicKey"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.PublicKey.RPID != testRPID {
			t.Fatalf("host %s: rpId = %q, want %q (%v)", host, out.PublicKey.RPID, testRPID, err)
		}
	}
}

func TestPasskeyAuditEventsAndRename(t *testing.T) {
	ctx := context.Background()
	a, store, rec := newPolicyAuth(t, theauth.WebAuthnConfig{})
	u, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "ev@example.com"})
	va := newVirtualAuthenticator(t)
	cred, err := register(t, a, u.ID, va)
	if err != nil {
		t.Fatal(err)
	}
	if err := login(t, a, u.ID, va); err != nil {
		t.Fatal(err)
	}
	if err := a.RenamePasskey(ctx, cred.ID, u.ID, "  Work laptop "); err != nil {
		t.Fatal(err)
	}
	creds, _ := store.WebAuthnCredentialsByUserID(ctx, u.ID)
	if len(creds) != 1 || creds[0].Name != "Work laptop" {
		t.Fatalf("rename not applied: %+v", creds)
	}
	other := ulid.New()
	if err := a.RenamePasskey(ctx, cred.ID, other, "x"); err == nil {
		t.Fatal("renaming another user's passkey must fail")
	}
	if err := a.RenamePasskey(ctx, cred.ID, u.ID, "   "); err == nil {
		t.Fatal("blank name must fail")
	}

	srv := httptest.NewServer(chiWith(a))
	t.Cleanup(srv.Close)
	tok := "session-token-for-test"
	now := time.Now()
	if _, err := store.CreateSession(ctx, theauth.Session{
		ID: ulid.New(), UserID: u.ID, TokenHash: crypto.HashToken(tok),
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), AuthLevel: "full",
	}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/auth/webauthn/credentials/"+cred.ID.String(), bytes.NewBufferString(`{"name":"Phone"}`))
	req.AddCookie(&http.Cookie{Name: "theauth_session", Value: tok})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PATCH rename: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodDelete, srv.URL+"/auth/webauthn/credentials/"+cred.ID.String(), nil)
	req.AddCookie(&http.Cookie{Name: "theauth_session", Value: tok})
	resp, _ = http.DefaultClient.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: %d", resp.StatusCode)
	}

	for _, typ := range []theauth.AuthEventType{
		theauth.AuthEventPasskeyAdded, theauth.AuthEventLoginSuccess,
		theauth.AuthEventPasskeyRenamed, theauth.AuthEventPasskeyRemoved,
	} {
		if rec.count(typ) == 0 {
			t.Errorf("event %q never fired", typ)
		}
	}
}

func chiWith(a *theauth.TheAuth) http.Handler {
	r := chi.NewRouter()
	a.Mount(r)
	return r
}
