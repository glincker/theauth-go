package theauth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
)

func newTestAuth(t *testing.T) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:      store,
		BaseURL:      "http://localhost",
		SessionTTL:   time.Hour,
		MagicLinkTTL: 15 * time.Minute,
		// Test defaults: keep production-realistic ratios but raise headroom
		// so multi-step e2e flows don't trip the per-email limit while still
		// letting dedicated tests assert the 429 boundary.
		RateLimitPerIP:    100,
		RateLimitPerEmail: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, store
}

func TestIssueAndValidateSession(t *testing.T) {
	a, store := newTestAuth(t)
	ctx := context.Background()
	user, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "i@v.com", CreatedAt: time.Now(), UpdatedAt: time.Now()})

	token, sess, err := theauth.IssueSessionForTest(a, ctx, user, "ua", "")
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || sess.ID.String() == "" {
		t.Fatal("issueSession returned empty")
	}

	gotSess, gotUser, err := theauth.ValidateSessionForTest(a, ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if gotSess.ID != sess.ID {
		t.Fatal("session ID mismatch")
	}
	if gotUser.Email != "i@v.com" {
		t.Fatal("user email mismatch")
	}
}

func TestValidateSessionInvalidToken(t *testing.T) {
	a, _ := newTestAuth(t)
	_, _, err := theauth.ValidateSessionForTest(a, context.Background(), "bogus")
	if err == nil {
		t.Fatal("expected error for bogus token")
	}
}

func TestValidateSessionRevoked(t *testing.T) {
	a, store := newTestAuth(t)
	ctx := context.Background()
	user, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "r@r.com", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	token, sess, _ := theauth.IssueSessionForTest(a, ctx, user, "", "")
	_ = store.RevokeSession(ctx, sess.ID)

	_, _, err := theauth.ValidateSessionForTest(a, ctx, token)
	if err == nil {
		t.Fatal("expected error for revoked session")
	}
}

// ---------- race tests (originally service_session_race_test.go) ----------

func newRaceAuth(t *testing.T) (*theauth.TheAuth, theauth.Storage) {
	t.Helper()
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:      store,
		BaseURL:      "http://localhost",
		SecureCookie: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, store
}

// TestSessionCreationRaceSameUser issues two concurrent session creations
// for the same user and asserts both succeed with distinct IDs. The
// in-memory adapter must not deadlock and must not produce a primary key
// collision.
func TestSessionCreationRaceSameUser(t *testing.T) {
	t.Parallel()
	a, store := newRaceAuth(t)
	ctx := context.Background()

	user := theauth.User{
		ID:        ulid.New(),
		Email:     "race@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	var (
		t1, t2 string
		s1, s2 theauth.Session
		e1, e2 error
		wg     sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		t1, s1, e1 = theauth.IssueSessionForTest(a, ctx, user, "ua", "ip")
	}()
	go func() {
		defer wg.Done()
		t2, s2, e2 = theauth.IssueSessionForTest(a, ctx, user, "ua", "ip")
	}()
	wg.Wait()

	if e1 != nil || e2 != nil {
		t.Fatalf("issueSession errors: e1=%v e2=%v", e1, e2)
	}
	if t1 == "" || t2 == "" {
		t.Fatalf("blank tokens: t1=%q t2=%q", t1, t2)
	}
	if t1 == t2 {
		t.Fatalf("tokens collided: %q", t1)
	}
	if s1.ID == s2.ID {
		t.Fatalf("session IDs collided: %s", s1.ID)
	}
}

// TestSessionLookupUnderWrites runs concurrent session creators against
// concurrent lookups. Lookups must never observe a zero-value or
// partially-initialized session struct.
func TestSessionLookupUnderWrites(t *testing.T) {
	t.Parallel()
	a, store := newRaceAuth(t)
	ctx := context.Background()

	const users = 100
	created := make([]theauth.User, users)
	tokens := make([]string, users)
	for i := 0; i < users; i++ {
		u := theauth.User{
			ID:        ulid.New(),
			Email:     "u" + ulid.New().String() + "@example.com",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		created[i], _ = store.CreateUser(ctx, u)
		tok, _, err := theauth.IssueSessionForTest(a, ctx, created[i], "", "")
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = tok
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: keep issuing new sessions.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _, _ = theauth.IssueSessionForTest(a, ctx, created[i%users], "ua", "ip")
				}
			}
		}(i)
	}

	// Readers: validate the known tokens; must always find a fully
	// populated session.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				sess, user, err := theauth.ValidateSessionForTest(a, ctx, tokens[i%users])
				if err != nil {
					t.Errorf("validate err: %v", err)
					return
				}
				if sess == nil || user == nil {
					t.Errorf("nil sess or user")
					return
				}
				if sess.UserID != user.ID {
					t.Errorf("session userID mismatch")
					return
				}
			}
		}(i)
	}

	// Let the workers churn briefly then stop.
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// ---------- magic-link tests (originally service_magiclink_test.go) ----------

func TestRequestMagicLinkCreatesAndEmails(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	if _, err := theauth.RequestMagicLinkForTest(a, ctx, "x@y.com"); err != nil {
		t.Fatal(err)
	}
}

func TestConsumeMagicLinkCreatesUserAndSession(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	token, err := theauth.RequestMagicLinkForTest(a, ctx, "consume@y.com")
	if err != nil {
		t.Fatal(err)
	}
	sessToken, user, err := theauth.ConsumeMagicLinkForTest(a, ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if sessToken == "" {
		t.Fatal("expected session token")
	}
	if user.Email != "consume@y.com" {
		t.Fatalf("got user email %q", user.Email)
	}
}

func TestConsumeMagicLinkTwiceFails(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	token, _ := theauth.RequestMagicLinkForTest(a, ctx, "twice@y.com")
	if _, _, err := theauth.ConsumeMagicLinkForTest(a, ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, _, err := theauth.ConsumeMagicLinkForTest(a, ctx, token); err == nil {
		t.Fatal("expected error on second consume")
	}
}

// TestLifecycleHooks_PasswordSignupAndSignin proves the v2.5 LifecycleHooks
// surface fires OnSignup once at password signup and OnSignin once at the
// subsequent signin. Covers issue #76. Uses the HTTP surface end-to-end so
// the assertion exercises the wiring at the same boundary consumers do.
func TestLifecycleHooks_PasswordSignupAndSignin(t *testing.T) {
	store := memory.New()
	var (
		mu            sync.Mutex
		signupCount   int
		signinCount   int
		signupMethod  theauth.SignupMethod
		signupUserID  theauth.ULID
		signinUserID  theauth.ULID
		seenSessionID theauth.ULID
	)

	a, err := theauth.New(theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		SessionTTL:        time.Hour,
		MagicLinkTTL:      15 * time.Minute,
		RateLimitPerIP:    100,
		RateLimitPerEmail: 100,
		LifecycleHooks: &theauth.LifecycleHooks{
			OnSignup: func(ctx context.Context, user *theauth.User, method theauth.SignupMethod) error {
				mu.Lock()
				signupCount++
				signupMethod = method
				signupUserID = user.ID
				mu.Unlock()
				return nil
			},
			OnSignin: func(ctx context.Context, user *theauth.User, sess *theauth.Session) error {
				mu.Lock()
				signinCount++
				signinUserID = user.ID
				seenSessionID = sess.ID
				mu.Unlock()
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	user, _, err := theauth.SignupWithPasswordForTest(a, ctx, "hooks@y.com", "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	mu.Lock()
	if signupCount != 1 || signinCount != 0 {
		t.Fatalf("after signup: want signup=1 signin=0; got signup=%d signin=%d", signupCount, signinCount)
	}
	if signupMethod != theauth.SignupMethodPassword {
		t.Fatalf("OnSignup method: want %q; got %q", theauth.SignupMethodPassword, signupMethod)
	}
	if signupUserID != user.ID {
		t.Fatalf("OnSignup user id mismatch: want %v; got %v", user.ID, signupUserID)
	}
	mu.Unlock()

	if _, _, err := theauth.SigninWithPasswordForTest(a, ctx, "hooks@y.com", "correct-horse-battery-staple", "ua", ""); err != nil {
		t.Fatalf("signin: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if signinCount != 1 {
		t.Fatalf("after signin: want signin=1; got %d", signinCount)
	}
	if signinUserID != user.ID {
		t.Fatalf("OnSignin user id mismatch: want %v; got %v", user.ID, signinUserID)
	}
	if seenSessionID == (theauth.ULID{}) {
		t.Fatal("OnSignin session was zero ULID")
	}
}

// TestLifecycleHooks_PanicRecovery proves a panicking hook does not bring
// down the request that triggered it. Validates the runLifecycleHook
// recovery semantic documented on LifecycleHooks.
func TestLifecycleHooks_PanicRecovery(t *testing.T) {
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		SessionTTL:        time.Hour,
		MagicLinkTTL:      15 * time.Minute,
		RateLimitPerIP:    100,
		RateLimitPerEmail: 100,
		LifecycleHooks: &theauth.LifecycleHooks{
			OnSignup: func(ctx context.Context, user *theauth.User, method theauth.SignupMethod) error {
				panic("intentional test panic")
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := theauth.SignupWithPasswordForTest(a, context.Background(), "panic@y.com", "correct-horse-battery-staple"); err != nil {
		t.Fatalf("signup must succeed despite hook panic; got %v", err)
	}
}

// TestLifecycleHooks_MagicLinkConsumeFiresHooks proves OnSignup fires once
// on the first magic-link consume (user just created) and only OnSignin
// fires on subsequent consumes for the same user. Covers issue #76 magic-
// link wiring.
func TestLifecycleHooks_MagicLinkConsumeFiresHooks(t *testing.T) {
	store := memory.New()
	var (
		mu          sync.Mutex
		signupCount int
		signinCount int
		lastMethod  theauth.SignupMethod
	)
	a, err := theauth.New(theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		SessionTTL:        time.Hour,
		MagicLinkTTL:      15 * time.Minute,
		RateLimitPerIP:    100,
		RateLimitPerEmail: 100,
		LifecycleHooks: &theauth.LifecycleHooks{
			OnSignup: func(ctx context.Context, u *theauth.User, m theauth.SignupMethod) error {
				mu.Lock()
				signupCount++
				lastMethod = m
				mu.Unlock()
				return nil
			},
			OnSignin: func(ctx context.Context, u *theauth.User, s *theauth.Session) error {
				mu.Lock()
				signinCount++
				mu.Unlock()
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// First consume: brand-new user. Expect OnSignup + OnSignin.
	tok1, err := theauth.RequestMagicLinkForTest(a, ctx, "ml@y.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := theauth.ConsumeMagicLinkForTest(a, ctx, tok1); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if signupCount != 1 || signinCount != 1 {
		t.Fatalf("first consume: want signup=1 signin=1; got signup=%d signin=%d", signupCount, signinCount)
	}
	if lastMethod != theauth.SignupMethodMagicLink {
		t.Fatalf("OnSignup method on magic-link consume: want %q; got %q", theauth.SignupMethodMagicLink, lastMethod)
	}
	mu.Unlock()

	// Second consume: existing user. Expect only OnSignin.
	tok2, err := theauth.RequestMagicLinkForTest(a, ctx, "ml@y.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := theauth.ConsumeMagicLinkForTest(a, ctx, tok2); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if signupCount != 1 {
		t.Fatalf("returning-user consume must NOT fire OnSignup; got signupCount=%d", signupCount)
	}
	if signinCount != 2 {
		t.Fatalf("returning-user consume must fire OnSignin; got signinCount=%d", signinCount)
	}
}

// TestTenancy_AutoCreatePersonalOrg proves the v2.5 TenancyConfig auto-
// provisions a personal organization on signup, adds the user as owner,
// and sets the session's active organization. Covers issue #77 auto-org.
func TestTenancy_AutoCreatePersonalOrg(t *testing.T) {
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		SessionTTL:        time.Hour,
		MagicLinkTTL:      15 * time.Minute,
		RateLimitPerIP:    100,
		RateLimitPerEmail: 100,
		Organizations:     &theauth.OrganizationsConfig{},
		Tenancy: &theauth.TenancyConfig{
			AutoCreatePersonalOrg: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	user, _, err := theauth.SignupWithPasswordForTest(a, ctx, "tenant@y.com", "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("signup: %v", err)
	}

	orgs, err := a.ListUserOrganizations(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListUserOrganizations: %v", err)
	}
	if len(orgs) != 1 {
		t.Fatalf("want 1 auto-provisioned org; got %d", len(orgs))
	}
	if orgs[0].Name != "tenant@y.com" {
		t.Fatalf("want default org name = email; got %q", orgs[0].Name)
	}
	members, err := a.ListOrganizationMembers(ctx, orgs[0].ID)
	if err != nil {
		t.Fatalf("ListOrganizationMembers: %v", err)
	}
	if len(members) != 1 || members[0].UserID != user.ID || members[0].Role != "owner" {
		t.Fatalf("want single owner member; got %+v", members)
	}
}

// TestTenancy_CustomNamerAndSlugger proves the Fn customization knobs are
// respected.
func TestTenancy_CustomNamerAndSlugger(t *testing.T) {
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		SessionTTL:        time.Hour,
		MagicLinkTTL:      15 * time.Minute,
		RateLimitPerIP:    100,
		RateLimitPerEmail: 100,
		Organizations:     &theauth.OrganizationsConfig{},
		Tenancy: &theauth.TenancyConfig{
			AutoCreatePersonalOrg: true,
			PersonalOrgNameFn: func(u *theauth.User) string {
				return "Workspace for " + u.Email
			},
			PersonalOrgSlugFn: func(u *theauth.User) string {
				return "ws-" + u.ID.String()[:8]
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	user, _, err := theauth.SignupWithPasswordForTest(a, ctx, "custom@y.com", "correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	orgs, _ := a.ListUserOrganizations(ctx, user.ID)
	if len(orgs) != 1 {
		t.Fatalf("want 1 org; got %d", len(orgs))
	}
	if orgs[0].Name != "Workspace for custom@y.com" {
		t.Fatalf("custom name: %q", orgs[0].Name)
	}
}

// TestTenancy_DisabledByDefault proves the library does NOT auto-create
// any organization when Tenancy is nil (back-compat guarantee).
func TestTenancy_DisabledByDefault(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	user, _, err := theauth.SignupWithPasswordForTest(a, ctx, "noauto@y.com", "correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	orgs, err := a.ListUserOrganizations(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListUserOrganizations: %v", err)
	}
	if len(orgs) != 0 {
		t.Fatalf("Tenancy off: want 0 orgs; got %d", len(orgs))
	}
}

// TestUserByID covers the v2.5 public lookup that previously forced
// consumers to reach into storage directly.
func TestUserByID(t *testing.T) {
	a, store := newTestAuth(t)
	ctx := context.Background()
	created, _ := store.CreateUser(ctx, theauth.User{
		ID:        ulid.New(),
		Email:     "lookup@y.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	got, err := a.UserByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if got == nil || got.Email != "lookup@y.com" {
		t.Fatalf("UserByID returned %+v", got)
	}
}

// TestLifecycleHooksFireThroughRealHTTPMount proves OnSignup,
// OnPasswordChange, and OnMFAEnabled fire when driven through the actual
// a.Mount() HTTP routes, not just the internal *ForTest forwarders used by
// TestLifecycleHooks_PasswordSignupAndSignin above. Before this fix,
// passwordhandlers/totphandlers/webauthnhandlers held the raw internal
// Service directly and called it without ever going through the
// hook-firing root forwarders, so LifecycleHooks silently never fired for
// any consumer using the batteries-included Mount() routes.
func TestLifecycleHooksFireThroughRealHTTPMount(t *testing.T) {
	store := memory.New()
	var (
		mu                  sync.Mutex
		signupCount         int
		signupMethod        theauth.SignupMethod
		passwordChangeCount int
		mfaEnabledCount     int
		mfaEnabledKind      theauth.MFAKind
	)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		SessionTTL:        time.Hour,
		MagicLinkTTL:      15 * time.Minute,
		RateLimitPerIP:    1000,
		RateLimitPerEmail: 1000,
		EncryptionKey:     key,
		TOTP:              &theauth.TOTPConfig{Issuer: "theauth-mount-hooks-test"},
		LifecycleHooks: &theauth.LifecycleHooks{
			OnSignup: func(ctx context.Context, user *theauth.User, method theauth.SignupMethod) error {
				mu.Lock()
				defer mu.Unlock()
				signupCount++
				signupMethod = method
				return nil
			},
			OnPasswordChange: func(ctx context.Context, user *theauth.User) error {
				mu.Lock()
				defer mu.Unlock()
				passwordChangeCount++
				return nil
			},
			OnMFAEnabled: func(ctx context.Context, user *theauth.User, kind theauth.MFAKind) error {
				mu.Lock()
				defer mu.Unlock()
				mfaEnabledCount++
				mfaEnabledKind = kind
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	a.Mount(r)
	srv := httptest.NewServer(r)
	defer srv.Close()
	theauth.SetBaseURLForTest(a, srv.URL)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	// --- Signup via the real /auth/email-password/signup HTTP route ---
	signupBody, _ := json.Marshal(map[string]string{"email": "mount-hooks@y.com", "password": "correct-horse-battery-staple"})
	resp, err := client.Post(srv.URL+"/auth/email-password/signup", "application/json", bytes.NewReader(signupBody))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("signup: got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	mu.Lock()
	if signupCount != 1 || signupMethod != theauth.SignupMethodPassword {
		t.Fatalf("OnSignup via Mount(): want count=1 method=password; got count=%d method=%q", signupCount, signupMethod)
	}
	mu.Unlock()

	// --- Password reset via the real /auth/email-password/reset HTTP route ---
	// The reset token is minted directly (bypassing email delivery, a
	// separately-tested concern) so this test isolates the HTTP reset
	// handler's hook wiring specifically.
	token, err := theauth.RequestPasswordResetForTest(a, context.Background(), "mount-hooks@y.com")
	if err != nil {
		t.Fatalf("RequestPasswordResetForTest: %v", err)
	}
	resetBody, _ := json.Marshal(map[string]string{"token": token, "newPassword": "second-correct-horse-battery"})
	resp, err = client.Post(srv.URL+"/auth/email-password/reset", "application/json", bytes.NewReader(resetBody))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset: got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	mu.Lock()
	if passwordChangeCount != 1 {
		t.Fatalf("OnPasswordChange via Mount(): want count=1; got %d", passwordChangeCount)
	}
	mu.Unlock()

	// Reset revokes every existing session, so the signup response's
	// cookie is now stale. Sign back in with the new password via the
	// real HTTP route to get a fresh session before exercising TOTP.
	signinBody, _ := json.Marshal(map[string]string{"email": "mount-hooks@y.com", "password": "second-correct-horse-battery"})
	signinResp, err := client.Post(srv.URL+"/auth/email-password/signin", "application/json", bytes.NewReader(signinBody))
	if err != nil {
		t.Fatal(err)
	}
	if signinResp.StatusCode != http.StatusOK {
		t.Fatalf("signin after reset: got %d", signinResp.StatusCode)
	}
	_ = signinResp.Body.Close()

	// --- TOTP enrollment via the real /auth/totp/enroll/* HTTP routes ---
	// The fresh session cookie rides along automatically via the client's
	// cookie jar, satisfying RequireAuth.
	beginResp, err := client.Post(srv.URL+"/auth/totp/enroll/begin", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if beginResp.StatusCode != http.StatusOK {
		t.Fatalf("enroll/begin: got %d", beginResp.StatusCode)
	}
	var enroll struct {
		Secret       string `json:"secret"`
		EnrollmentID string `json:"enrollmentId"`
	}
	decodeErr := json.NewDecoder(beginResp.Body).Decode(&enroll)
	_ = beginResp.Body.Close()
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}

	code, err := totp.GenerateCode(enroll.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	finishBody, _ := json.Marshal(map[string]string{"enrollmentId": enroll.EnrollmentID, "code": code})
	finishResp, err := client.Post(srv.URL+"/auth/totp/enroll/finish", "application/json", bytes.NewReader(finishBody))
	if err != nil {
		t.Fatal(err)
	}
	if finishResp.StatusCode != http.StatusOK {
		t.Fatalf("enroll/finish: got %d", finishResp.StatusCode)
	}
	_ = finishResp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if mfaEnabledCount != 1 || mfaEnabledKind != theauth.MFAKindTOTP {
		t.Fatalf("OnMFAEnabled via Mount(): want count=1 kind=totp; got count=%d kind=%q", mfaEnabledCount, mfaEnabledKind)
	}
}
