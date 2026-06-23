package theauth_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

const validPassword = "correct-horse-battery-staple" // > 12 chars

func TestSignupWithPasswordHappyPath(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	user, sess, err := theauth.SignupWithPasswordForTest(a, ctx, "Sign@Up.com", validPassword)
	if err != nil {
		t.Fatal(err)
	}
	if sess == "" {
		t.Fatal("expected session token")
	}
	// Email should be canonicalized to lowercase.
	if user.Email != "sign@up.com" {
		t.Fatalf("expected lowercased email; got %q", user.Email)
	}
	// Signin with the same creds should work (case-insensitive email).
	tok, gotUser, err := theauth.SigninWithPasswordForTest(a, ctx, "sign@up.com", validPassword, "ua", "")
	if err != nil {
		t.Fatal(err)
	}
	if tok == "" {
		t.Fatal("expected signin token")
	}
	if gotUser.ID != user.ID {
		t.Fatal("signin returned different user")
	}
}

func TestSignupWeakPasswordRejected(t *testing.T) {
	a, _ := newTestAuth(t)
	_, _, err := theauth.SignupWithPasswordForTest(a, context.Background(), "weak@h.com", "shortpw")
	var te *theauth.TheAuthError
	if !errors.As(err, &te) {
		t.Fatalf("expected TheAuthError; got %v", err)
	}
	if te.Code != theauth.CodeWeakPassword {
		t.Fatalf("got code %q", te.Code)
	}
}

func TestSignupEmailTakenRejected(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	if _, _, err := theauth.SignupWithPasswordForTest(a, ctx, "dup@h.com", validPassword); err != nil {
		t.Fatal(err)
	}
	_, _, err := theauth.SignupWithPasswordForTest(a, ctx, "dup@h.com", validPassword)
	var te *theauth.TheAuthError
	if !errors.As(err, &te) || te.Code != theauth.CodeEmailTaken {
		t.Fatalf("expected email_taken; got %v", err)
	}
}

func TestSigninWrongPasswordReturnsInvalidCredentials(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	if _, _, err := theauth.SignupWithPasswordForTest(a, ctx, "u@h.com", validPassword); err != nil {
		t.Fatal(err)
	}
	_, _, err := theauth.SigninWithPasswordForTest(a, ctx, "u@h.com", "totally-wrong-password", "", "")
	var te *theauth.TheAuthError
	if !errors.As(err, &te) || te.Code != theauth.CodeInvalidCredentials {
		t.Fatalf("expected invalid_credentials; got %v", err)
	}
}

// Anti-enumeration: signin against an unknown email returns the same code as
// signin with a wrong password.
func TestSigninUnknownEmailReturnsInvalidCredentials(t *testing.T) {
	a, _ := newTestAuth(t)
	_, _, err := theauth.SigninWithPasswordForTest(a, context.Background(), "ghost@h.com", validPassword, "", "")
	var te *theauth.TheAuthError
	if !errors.As(err, &te) || te.Code != theauth.CodeInvalidCredentials {
		t.Fatalf("expected invalid_credentials; got %v", err)
	}
}

// A magic-link-only user (no password set) trying to sign in via password
// must also surface invalid_credentials.
func TestSigninMagicLinkOnlyUserReturnsInvalidCredentials(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	// Create the user via magic-link consume so no password is set.
	tok, err := theauth.RequestMagicLinkForTest(a, ctx, "mlonly@h.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := theauth.ConsumeMagicLinkForTest(a, ctx, tok); err != nil {
		t.Fatal(err)
	}
	_, _, err = theauth.SigninWithPasswordForTest(a, ctx, "mlonly@h.com", validPassword, "", "")
	var te *theauth.TheAuthError
	if !errors.As(err, &te) || te.Code != theauth.CodeInvalidCredentials {
		t.Fatalf("expected invalid_credentials; got %v", err)
	}
}

func TestRequestPasswordResetUnknownEmailSilentSuccess(t *testing.T) {
	a, _ := newTestAuth(t)
	tok, err := theauth.RequestPasswordResetForTest(a, context.Background(), "missing@h.com")
	if err != nil {
		t.Fatalf("expected silent success; got %v", err)
	}
	if tok != "" {
		t.Fatalf("expected empty token for unknown email; got %q", tok)
	}
}

func TestRequestPasswordResetKnownEmailMintsToken(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	if _, _, err := theauth.SignupWithPasswordForTest(a, ctx, "r@h.com", validPassword); err != nil {
		t.Fatal(err)
	}
	tok, err := theauth.RequestPasswordResetForTest(a, ctx, "r@h.com")
	if err != nil {
		t.Fatal(err)
	}
	if tok == "" {
		t.Fatal("expected reset token")
	}
}

func TestResetPasswordHappyPathRevokesSessions(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	_, sessOld, err := theauth.SignupWithPasswordForTest(a, ctx, "rp@h.com", validPassword)
	if err != nil {
		t.Fatal(err)
	}
	// Original session should be valid before reset.
	if _, _, err := theauth.ValidateSessionForTest(a, ctx, sessOld); err != nil {
		t.Fatal(err)
	}

	tok, err := theauth.RequestPasswordResetForTest(a, ctx, "rp@h.com")
	if err != nil {
		t.Fatal(err)
	}
	newPW := "brand-new-password-123"
	if err := theauth.ResetPasswordForTest(a, ctx, tok, newPW); err != nil {
		t.Fatal(err)
	}
	// Original session must now be invalid (revoked).
	if _, _, err := theauth.ValidateSessionForTest(a, ctx, sessOld); err == nil {
		t.Fatal("expected old session to be revoked")
	}
	// Old password no longer works.
	if _, _, err := theauth.SigninWithPasswordForTest(a, ctx, "rp@h.com", validPassword, "", ""); err == nil {
		t.Fatal("expected old password to be rejected")
	}
	// New password works.
	tokNew, _, err := theauth.SigninWithPasswordForTest(a, ctx, "rp@h.com", newPW, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if tokNew == "" {
		t.Fatal("expected new signin token")
	}
}

func TestResetPasswordSingleUse(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	if _, _, err := theauth.SignupWithPasswordForTest(a, ctx, "su@h.com", validPassword); err != nil {
		t.Fatal(err)
	}
	tok, err := theauth.RequestPasswordResetForTest(a, ctx, "su@h.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := theauth.ResetPasswordForTest(a, ctx, tok, "first-reset-pw-1"); err != nil {
		t.Fatal(err)
	}
	err = theauth.ResetPasswordForTest(a, ctx, tok, "second-reset-pw-2")
	var te *theauth.TheAuthError
	if !errors.As(err, &te) || te.Code != theauth.CodePasswordResetInvalid {
		t.Fatalf("expected password_reset_invalid on reuse; got %v", err)
	}
}

func TestResetPasswordInvalidToken(t *testing.T) {
	a, _ := newTestAuth(t)
	err := theauth.ResetPasswordForTest(a, context.Background(), "not-a-real-token", validPassword)
	var te *theauth.TheAuthError
	if !errors.As(err, &te) || te.Code != theauth.CodePasswordResetInvalid {
		t.Fatalf("expected password_reset_invalid; got %v", err)
	}
}

func TestResetPasswordWeakPassword(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	if _, _, err := theauth.SignupWithPasswordForTest(a, ctx, "weak@h.com", validPassword); err != nil {
		t.Fatal(err)
	}
	tok, err := theauth.RequestPasswordResetForTest(a, ctx, "weak@h.com")
	if err != nil {
		t.Fatal(err)
	}
	err = theauth.ResetPasswordForTest(a, ctx, tok, "short")
	var te *theauth.TheAuthError
	if !errors.As(err, &te) || te.Code != theauth.CodeWeakPassword {
		t.Fatalf("expected weak_password; got %v", err)
	}
}

func TestSignupEmailMustParseAsAddress(t *testing.T) {
	a, _ := newTestAuth(t)
	_, _, err := theauth.SignupWithPasswordForTest(a, context.Background(), "not-an-email", validPassword)
	if err == nil {
		t.Fatal("expected error for malformed email")
	}
	// Should be invalid_credentials per anti-enumeration policy.
	if !strings.Contains(err.Error(), "invalid_credentials") {
		t.Fatalf("got %v", err)
	}
}

// ---------- fuzz tests (originally service_password_fuzz_test.go) ----------

// FuzzEmailValidation drives arbitrary input strings through the email
// validator. The invariant is "never panic" across RFC 5322 edge cases
// such as quoted local parts, IDN punycode, very long local parts,
// embedded NULs, leading or trailing whitespace, and the literal "<>".
func FuzzEmailValidation(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("user@example.com"))
	f.Add([]byte("\"quoted local\"@example.com"))
	f.Add([]byte("not-an-email"))
	f.Add([]byte("<>"))
	f.Add([]byte("user@xn--bcher-kva.example"))
	f.Add([]byte("a@b"))
	f.Add([]byte("user\x00@example.com"))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			input = input[:4096]
		}
		_, _ = theauth.ValidateEmailForTest(string(input))
		// No assertion beyond "did not panic". Returning an error for
		// malformed input is the documented behavior and is fine.
	})
}

// ---------- OAuth race tests (originally service_oauth_race_test.go) ----------

// TestOAuthStateConcurrentReadWrite spawns interleaving writers (driving
// /auth/providers/stub/start which stores state) and readers (driving the
// callback path which reads + deletes state). The test asserts no panic
// and no data race under -race.
func TestOAuthStateConcurrentReadWrite(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:           memory.New(),
		BaseURL:           "http://localhost",
		EncryptionKey:     key,
		PostLoginRedirect: "/",
		Providers:         []theauth.Provider{&stubProvider{name: "stub"}},
		// Bump the per-IP limit well above the writer count so the test
		// exercises the state map under load rather than the rate limiter.
		RateLimitPerIP: 10_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	r := chi.NewRouter()
	a.Mount(r)

	const writers = 500
	const readers = 500
	var wg sync.WaitGroup
	wg.Add(writers + readers)

	// Writers exercise the start endpoint, which writes to the shared
	// oauthStates sync.Map.
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/auth/providers/stub/start", nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
		}()
	}

	// Readers exercise the callback endpoint with arbitrary state values.
	// Most will miss (state never stored), the rest hit the LoadAndDelete
	// path under the same map. The point is to interleave reads and writes.
	for i := 0; i < readers; i++ {
		go func(i int) {
			defer wg.Done()
			rb := make([]byte, 16)
			_, _ = rand.Read(rb)
			state := hex.EncodeToString(rb)
			// State cookie matches the query so the handler reaches the
			// service layer's LoadAndDelete branch.
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/providers/stub/callback?state=%s&code=x", state), nil)
			req.AddCookie(&http.Cookie{Name: "theauth_oauth_state", Value: state})
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
		}(i)
	}
	wg.Wait()

	// Sanity: trigger one more start + callback round trip and ensure
	// the map still behaves.
	req := httptest.NewRequest(http.MethodGet, "/auth/providers/stub/start", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("post-race start returned %d, want 302", rec.Code)
	}
	_ = context.Background()
}

// ---------- shared fuzz helpers (originally fuzz_helpers_test.go) ----------

// stubProvider is a no-network OAuth provider used by fuzz targets that
// need a registered {name} route without actually exchanging codes.
type stubProvider struct{ name string }

func (s *stubProvider) Name() string { return s.name }

func (s *stubProvider) AuthURL(state, codeChallenge, redirectURI string, scopes []string) string {
	return "https://example.invalid/authorize?state=" + state
}

func (s *stubProvider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*theauth.ProviderToken, error) {
	return &theauth.ProviderToken{AccessToken: "stub"}, nil
}

func (s *stubProvider) UserInfo(ctx context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	return &theauth.ProviderUser{ID: "stub-id", Email: "stub@example.invalid"}, nil
}

// newOAuthFuzzAuth returns a TheAuth with one stub provider registered
// plus a chi router that has the standard /auth routes mounted on it.
func newOAuthFuzzAuth(t testing.TB) (*theauth.TheAuth, http.Handler) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("read key: %v", err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:           memory.New(),
		BaseURL:           "http://localhost",
		EncryptionKey:     key,
		PostLoginRedirect: "/",
		Providers:         []theauth.Provider{&stubProvider{name: "stub"}},
	})
	if err != nil {
		t.Fatalf("new theauth: %v", err)
	}
	t.Cleanup(a.Close)
	r := chi.NewRouter()
	a.Mount(r)
	return a, r
}
