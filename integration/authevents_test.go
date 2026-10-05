package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/integration/internal/testutil"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
)

type eventLog struct {
	mu     sync.Mutex
	events []theauth.AuthEvent
}

func (l *eventLog) sink(_ context.Context, e theauth.AuthEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) find(typ theauth.AuthEventType) []theauth.AuthEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []theauth.AuthEvent
	for _, e := range l.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func newEventAuth(t *testing.T) (*theauth.TheAuth, *memory.Store, *eventLog) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	log := &eventLog{}
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		EncryptionKey:     key,
		TOTP:              &theauth.TOTPConfig{Issuer: "Events"},
		RateLimitPerIP:    1000,
		RateLimitPerEmail: 1000,
		AuthEventSink:     log.sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, store, log
}

func TestAuthEventsEveryTypeFires(t *testing.T) {
	a, _, log := newEventAuth(t)
	ctx := context.Background()
	const email = "events@h.com"
	const pw = "twelve-chars-min-pw"

	u, _, err := testutil.SignupWithPasswordForTest(a, ctx, email, pw)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := testutil.SigninWithPasswordForTest(a, ctx, email, "wrong-password-xx", "ua", "203.0.113.77"); err == nil {
		t.Fatal("wrong password must fail")
	}
	if _, _, err := testutil.SigninWithPasswordForTest(a, ctx, "nobody@h.com", pw, "ua", "2001:db8:abcd:1234::1"); err == nil {
		t.Fatal("unknown user must fail")
	}
	if _, _, err := testutil.SigninWithPasswordForTest(a, ctx, email, pw, "ua", "203.0.113.77"); err != nil {
		t.Fatal(err)
	}

	enr, err := testutil.BeginTOTPEnrollmentForTest(a, ctx, u.ID, email)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(enr.Secret, time.Now())
	codes, err := testutil.FinishTOTPEnrollmentForTest(a, ctx, u.ID, enr.EnrollmentID, code)
	if err != nil {
		t.Fatal(err)
	}
	pend, _, err := testutil.IssuePending2FAForTest(a, ctx, u.ID, "ua", "203.0.113.77")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := testutil.VerifyTOTPForTest(a, ctx, pend, "000000"); err == nil {
		t.Fatal("bad totp must fail")
	}
	good, _ := totp.GenerateCode(enr.Secret, time.Now())
	if _, _, err := testutil.VerifyTOTPForTest(a, ctx, pend, good); err != nil {
		t.Fatal(err)
	}
	pend2, _, _ := testutil.IssuePending2FAForTest(a, ctx, u.ID, "ua", "203.0.113.77")
	if _, _, err := testutil.ConsumeRecoveryCodeForTest(a, ctx, pend2, codes[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RegenerateRecoveryCodes(ctx, u.ID); err != nil {
		t.Fatal(err)
	}

	tok, err := testutil.RequestPasswordResetForTest(a, ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	if err := testutil.ResetPasswordForTest(a, ctx, tok, "another-twelve-chars-pw"); err != nil {
		t.Fatal(err)
	}

	_, sess, err := testutil.IssueSessionForTest(a, ctx, *u, "ua", "203.0.113.77")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RevokeSession(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	a.RecordTokenMinted(ctx, u.ID, "api")
	a.RecordTokenRevoked(ctx, u.ID, "api")

	srv := newServer(t, a)
	tokFull, _, _ := testutil.IssueSessionForTest(a, ctx, *u, "ua", "203.0.113.77")
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/auth/totp", nil)
	req.AddCookie(&http.Cookie{Name: "theauth_session", Value: tokFull})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /auth/totp: %d", resp.StatusCode)
	}

	want := []theauth.AuthEventType{
		theauth.AuthEventLoginSuccess, theauth.AuthEventLoginFailure,
		theauth.AuthEventMFASuccess, theauth.AuthEventMFAFailure,
		theauth.AuthEventPasswordChanged, theauth.AuthEventPasswordResetRequested, theauth.AuthEventPasswordResetCompleted,
		theauth.AuthEventTOTPEnrolled, theauth.AuthEventTOTPDisabled, theauth.AuthEventRecoveryCodesRegen,
		theauth.AuthEventSessionRevoked, theauth.AuthEventTokenMinted, theauth.AuthEventTokenRevoked,
	}
	for _, typ := range want {
		if len(log.find(typ)) == 0 {
			t.Errorf("event %q never fired", typ)
		}
	}

	fails := log.find(theauth.AuthEventLoginFailure)
	if len(fails) != 2 {
		t.Fatalf("want 2 login failures, got %d", len(fails))
	}
	if fails[0].IPPrefix != "203.0.113.0/24" || fails[0].UserID != u.ID.String() || fails[0].Reason != "bad_password" {
		t.Errorf("bad-password failure event wrong: %+v", fails[0])
	}
	if fails[1].IPPrefix != "2001:db8:abcd::/48" || fails[1].UserID != "" {
		t.Errorf("unknown-user failure event wrong: %+v", fails[1])
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, e := range log.events {
		if s := fmt.Sprintf("%+v", e); strings.Contains(s, "@") || strings.Contains(s, "203.0.113.77") {
			t.Errorf("event leaks PII: %s", s)
		}
	}
}

func TestAuthEventChannelSinkDropsWhenFull(t *testing.T) {
	ch := make(chan theauth.AuthEvent, 1)
	sink := theauth.AuthEventChannelSink(ch)
	sink(context.Background(), theauth.AuthEvent{Type: theauth.AuthEventLoginSuccess})
	sink(context.Background(), theauth.AuthEvent{Type: theauth.AuthEventLoginFailure})
	if len(ch) != 1 || (<-ch).Type != theauth.AuthEventLoginSuccess {
		t.Fatal("full channel must drop, not block")
	}
}

func TestAuthEventSinkPanicIsContained(t *testing.T) {
	key := make([]byte, 32)
	a, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", EncryptionKey: key,
		AuthEventSink: func(context.Context, theauth.AuthEvent) { panic("boom") },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	a.RecordTokenMinted(context.Background(), ulid.New(), "api")
}

func newServer(t *testing.T, a *theauth.TheAuth) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}
