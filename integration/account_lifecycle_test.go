package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/integration/internal/testutil"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
)

const lcPassword = "correct-horse-battery-1"

func lcAuth(t *testing.T, mutate func(*theauth.Config)) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cfg := theauth.Config{
		Storage:           store,
		BaseURL:           "http://localhost",
		EncryptionKey:     key,
		TOTP:              &theauth.TOTPConfig{Issuer: "T"},
		AccountState:      true,
		RateLimitPerIP:    10000,
		RateLimitPerEmail: 10000,
		LoginThrottle:     &theauth.LoginThrottleConfig{Disabled: true},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := theauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, store
}

func lcSignup(t *testing.T, a *theauth.TheAuth, email string) *theauth.User {
	t.Helper()
	u, _, err := testutil.SignupWithPasswordForTest(a, context.Background(), email, lcPassword)
	if err != nil {
		t.Fatalf("signup %s: %v", email, err)
	}
	return u
}

func lcSignin(a *theauth.TheAuth, email, pw string) (string, error) {
	tok, _, err := testutil.SigninWithPasswordForTest(a, context.Background(), email, pw, "ua", "10.0.0.1")
	return tok, err
}

func lcCode(err error) string {
	var te *theauth.TheAuthError
	if errors.As(err, &te) {
		return te.Code
	}
	return ""
}

func lcEnrollTOTP(t *testing.T, a *theauth.TheAuth, u *theauth.User) []string {
	t.Helper()
	ctx := context.Background()
	enr, err := testutil.BeginTOTPEnrollmentForTest(a, ctx, u.ID, u.Email)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(enr.Secret, time.Now())
	codes, err := testutil.FinishTOTPEnrollmentForTest(a, ctx, u.ID, enr.EnrollmentID, code)
	if err != nil {
		t.Fatal(err)
	}
	return codes
}

func lcResetViaToken(t *testing.T, a *theauth.TheAuth, email, newPassword string) {
	t.Helper()
	ctx := context.Background()
	tok, err := testutil.RequestPasswordResetForTest(a, ctx, email)
	if err != nil || tok == "" {
		t.Fatalf("request reset: %q %v", tok, err)
	}
	if err := testutil.ResetPasswordForTest(a, ctx, tok, newPassword); err != nil {
		t.Fatalf("reset: %v", err)
	}
}

func TestMustChangePasswordBlocksPasswordSignin(t *testing.T) {
	a, _ := lcAuth(t, nil)
	ctx := context.Background()
	u := lcSignup(t, a, "force@lc.com")
	oldTok, err := lcSignin(a, "force@lc.com", lcPassword)
	if err != nil {
		t.Fatal(err)
	}

	if err := a.SetMustChangePassword(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := testutil.ValidateSessionForTest(a, ctx, oldTok); err == nil {
		t.Fatal("existing sessions must be revoked when the flag is set")
	}
	if _, err := lcSignin(a, "force@lc.com", lcPassword); lcCode(err) != theauth.CodePasswordChangeRequired {
		t.Fatalf("flagged signin: err = %v, want %s", err, theauth.CodePasswordChangeRequired)
	}
	// A wrong password keeps looking like a wrong password.
	if _, err := lcSignin(a, "force@lc.com", "wrong-wrong-wrong-1"); lcCode(err) != theauth.CodeInvalidCredentials {
		t.Fatalf("wrong password: err = %v", err)
	}

	lcResetViaToken(t, a, "force@lc.com", "a-brand-new-passphrase-2")
	if _, err := lcSignin(a, "force@lc.com", "a-brand-new-passphrase-2"); err != nil {
		t.Fatalf("signin after reset must work, got %v", err)
	}
}

func TestMustChangePasswordBlocksEveryIssuePath(t *testing.T) {
	prov := &hardenProvider{user: theauth.ProviderUser{ID: "p1", Email: "paths@lc.com", EmailVerified: true}}
	a, _ := lcAuth(t, func(c *theauth.Config) {
		c.Providers = []theauth.Provider{prov}
		c.SessionLinks = &theauth.SessionLinksConfig{
			CredentialChecker: theauth.CredentialCheckerFunc(func(context.Context, string) error { return nil }),
		}
	})
	ctx := context.Background()
	u := lcSignup(t, a, "paths@lc.com")
	linkTok, _, err := a.MintSessionLink(ctx, theauth.MintSessionLinkInput{UserID: u.ID})
	if err != nil {
		t.Fatal(err)
	}
	mlTok, err := testutil.RequestMagicLinkForTest(a, ctx, "paths@lc.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetMustChangePassword(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}

	t.Run("magic link", func(t *testing.T) {
		if _, _, err := testutil.ConsumeMagicLinkForTest(a, ctx, mlTok); lcCode(err) != theauth.CodePasswordChangeRequired {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("session link", func(t *testing.T) {
		if _, _, err := a.ConsumeSessionLink(ctx, linkTok, "ua", "10.0.0.1"); lcCode(err) != theauth.CodePasswordChangeRequired {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("direct issue", func(t *testing.T) {
		if _, _, err := testutil.IssueSessionForTest(a, ctx, *u, "ua", "ip"); lcCode(err) != theauth.CodePasswordChangeRequired {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("oauth callback", func(t *testing.T) {
		srv := httptest.NewServer(mountedHandler(a))
		defer srv.Close()
		resp, err := noFollow.Get(srv.URL + "/auth/providers/hard/start")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		var cookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "theauth_oauth_state" {
				cookie = c
			}
		}
		loc := resp.Header.Get("Location")
		state := loc[strings.Index(loc, "state=")+len("state="):]
		if i := strings.IndexByte(state, '&'); i >= 0 {
			state = state[:i]
		}
		req, _ := http.NewRequest("GET", srv.URL+"/auth/providers/hard/callback?code=c&state="+state, nil)
		req.AddCookie(cookie)
		cb, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = cb.Body.Close()
		for _, c := range cb.Cookies() {
			if c.Name == "theauth_session" && c.Value != "" {
				t.Fatalf("oauth callback must not set a session for a flagged user")
			}
		}
	})
}

func mountedHandler(a *theauth.TheAuth) http.Handler {
	r := chi.NewRouter()
	a.Mount(r)
	return r
}

func TestMustChangePasswordWithTOTPDoesNotMintPendingSession(t *testing.T) {
	a, _ := lcAuth(t, nil)
	ctx := context.Background()
	u := lcSignup(t, a, "totpforce@lc.com")
	lcEnrollTOTP(t, a, u)
	if err := a.SetMustChangePassword(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := lcSignin(a, "totpforce@lc.com", lcPassword); lcCode(err) != theauth.CodePasswordChangeRequired {
		t.Fatalf("err = %v, want %s", err, theauth.CodePasswordChangeRequired)
	}
}

func TestResetPasswordAdminRequirePasswordChange(t *testing.T) {
	a, _ := lcAuth(t, nil)
	ctx := context.Background()
	lcSignup(t, a, "adminreset@lc.com")
	if err := a.ResetPasswordAdmin(ctx, "adminreset@lc.com", "temporary-passphrase-3", theauth.RequirePasswordChange()); err != nil {
		t.Fatal(err)
	}
	if _, err := lcSignin(a, "adminreset@lc.com", "temporary-passphrase-3"); lcCode(err) != theauth.CodePasswordChangeRequired {
		t.Fatalf("err = %v", err)
	}
	lcResetViaToken(t, a, "adminreset@lc.com", "chosen-by-the-user-4")
	if _, err := lcSignin(a, "adminreset@lc.com", "chosen-by-the-user-4"); err != nil {
		t.Fatal(err)
	}
	// A plain admin reset clears a pending flag.
	if err := a.ResetPasswordAdmin(ctx, "adminreset@lc.com", "temporary-passphrase-3", theauth.RequirePasswordChange()); err != nil {
		t.Fatal(err)
	}
	if err := a.ResetPasswordAdmin(ctx, "adminreset@lc.com", "operator-chosen-pass-5"); err != nil {
		t.Fatal(err)
	}
	if _, err := lcSignin(a, "adminreset@lc.com", "operator-chosen-pass-5"); err != nil {
		t.Fatalf("plain admin reset must clear the flag: %v", err)
	}
}

func TestAccountStateDisabledConfig(t *testing.T) {
	a, _ := lcAuth(t, func(c *theauth.Config) { c.AccountState = false })
	ctx := context.Background()
	u := lcSignup(t, a, "off@lc.com")
	if err := a.SetMustChangePassword(ctx, u.ID, true); !errors.Is(err, theauth.ErrAccountStateDisabled) {
		t.Fatalf("SetMustChangePassword: %v", err)
	}
	if err := a.ResetPasswordAdmin(ctx, "off@lc.com", "temporary-passphrase-3", theauth.RequirePasswordChange()); !errors.Is(err, theauth.ErrAccountStateDisabled) {
		t.Fatalf("ResetPasswordAdmin: %v", err)
	}
	if err := a.DisableUser(ctx, u.ID); !errors.Is(err, theauth.ErrAccountStateDisabled) {
		t.Fatalf("DisableUser: %v", err)
	}
}

func TestAccountStateRequiresCapability(t *testing.T) {
	_, err := theauth.New(theauth.Config{
		CoreStorage: coreOnly{memory.New()}, BaseURL: "http://x", AccountState: true,
	})
	if !errors.Is(err, theauth.ErrStorageMissingCapability) {
		t.Fatalf("err = %v", err)
	}
}

func TestDisableAndEnableUser(t *testing.T) {
	a, _ := lcAuth(t, nil)
	ctx := context.Background()
	u := lcSignup(t, a, "dis@lc.com")
	tok, err := lcSignin(a, "dis@lc.com", lcPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.DisableUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := testutil.ValidateSessionForTest(a, ctx, tok); err == nil {
		t.Fatal("disabling must revoke sessions")
	}
	if _, err := lcSignin(a, "dis@lc.com", lcPassword); lcCode(err) != theauth.CodeAccountDisabled {
		t.Fatalf("err = %v, want %s", err, theauth.CodeAccountDisabled)
	}
	if err := a.EnableUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := lcSignin(a, "dis@lc.com", lcPassword); err != nil {
		t.Fatalf("signin after enable: %v", err)
	}
}

func TestSessionPolicyEvictOldest(t *testing.T) {
	a, store := lcAuth(t, func(c *theauth.Config) {
		c.SessionPolicy = &theauth.SessionPolicy{MaxConcurrentSessions: 2}
	})
	ctx := context.Background()
	lcSignup(t, a, "cap@lc.com") // signup issues session 1
	t2, err := lcSignin(a, "cap@lc.com", lcPassword)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	t3, err := lcSignin(a, "cap@lc.com", lcPassword)
	if err != nil {
		t.Fatalf("third sign-in must evict, got %v", err)
	}
	for name, tok := range map[string]string{"second": t2, "third": t3} {
		if _, _, err := testutil.ValidateSessionForTest(a, ctx, tok); err != nil {
			t.Errorf("%s session must survive: %v", name, err)
		}
	}
	u, _ := store.UserByEmail(ctx, "cap@lc.com")
	list, err := a.ListSessions(ctx, u.ID, theauth.ULID{})
	if err != nil || len(list) != 2 {
		t.Fatalf("live sessions = %d, %v; want 2", len(list), err)
	}
}

func TestSessionPolicyReject(t *testing.T) {
	a, _ := lcAuth(t, func(c *theauth.Config) {
		c.SessionPolicy = &theauth.SessionPolicy{MaxConcurrentSessions: 1, Overflow: theauth.SessionReject}
	})
	lcSignup(t, a, "rej@lc.com")
	if _, err := lcSignin(a, "rej@lc.com", lcPassword); lcCode(err) != theauth.CodeSessionLimit {
		t.Fatalf("err = %v, want %s", err, theauth.CodeSessionLimit)
	}
}

func TestSessionPolicyAppliesAtTOTPPromotion(t *testing.T) {
	a, _ := lcAuth(t, func(c *theauth.Config) {
		c.SessionPolicy = &theauth.SessionPolicy{MaxConcurrentSessions: 1, Overflow: theauth.SessionReject}
	})
	ctx := context.Background()
	u := lcSignup(t, a, "totpcap@lc.com") // session 1, no TOTP yet
	codes := lcEnrollTOTP(t, a, u)
	pend, err := lcSignin(a, "totpcap@lc.com", lcPassword)
	if err != nil {
		t.Fatalf("password step issues only a pending session: %v", err)
	}
	if _, _, err := testutil.ConsumeRecoveryCodeForTest(a, ctx, pend, codes[0]); lcCode(err) != theauth.CodeSessionLimit {
		t.Fatalf("promotion over the cap: err = %v, want %s", err, theauth.CodeSessionLimit)
	}
	// The recovery code was not spent by the refusal.
	if st, err := a.TOTPStatus(ctx, u.ID); err != nil || st.RecoveryCodesRemaining != len(codes) {
		t.Fatalf("recovery codes remaining = %+v, %v; want %d", st, err, len(codes))
	}
}

func TestSessionPolicyEvictOnTOTPPromotionKeepsPromotedSession(t *testing.T) {
	a, _ := lcAuth(t, func(c *theauth.Config) {
		c.SessionPolicy = &theauth.SessionPolicy{MaxConcurrentSessions: 1}
	})
	ctx := context.Background()
	u := lcSignup(t, a, "totpevict@lc.com")
	first, err := lcSignin(a, "totpevict@lc.com", lcPassword)
	if err != nil {
		t.Fatal(err)
	}
	codes := lcEnrollTOTP(t, a, u)
	pend, err := lcSignin(a, "totpevict@lc.com", lcPassword)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := testutil.ConsumeRecoveryCodeForTest(a, ctx, pend, codes[0])
	if err != nil {
		t.Fatalf("promotion must evict, got %v", err)
	}
	if _, _, err := testutil.ValidateSessionForTest(a, ctx, tok); err != nil {
		t.Fatalf("promoted session must be usable: %v", err)
	}
	if _, _, err := testutil.ValidateSessionForTest(a, ctx, first); err == nil {
		t.Fatal("older session must be evicted")
	}
}

type lcHook struct{ deleted atomic.Pointer[theauth.User] }

func TestSelfServiceAccountDeletion(t *testing.T) {
	var hook lcHook
	a, store := lcAuth(t, func(c *theauth.Config) {
		c.AccountDeletion = &theauth.AccountDeletionConfig{}
		c.Audit = &theauth.AuditConfig{FlushInterval: 10 * time.Millisecond}
		c.LifecycleHooks = &theauth.LifecycleHooks{
			OnAccountDeleted: func(_ context.Context, u *theauth.User) error {
				hook.deleted.Store(u)
				return nil
			},
		}
	})
	ctx := context.Background()
	u := lcSignup(t, a, "bye@lc.com")
	other := lcSignup(t, a, "stay@lc.com")
	tok, err := lcSignin(a, "bye@lc.com", lcPassword)
	if err != nil {
		t.Fatal(err)
	}
	lcEnrollTOTP(t, a, u)
	srv := httptest.NewServer(mountedHandler(a))
	defer srv.Close()

	// Unauthenticated.
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/account", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous DELETE /account = %d, want 401", resp.StatusCode)
	}

	resp, _ = authedDo(t, http.MethodDelete, srv.URL+"/account", tok, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /account = %d, want 204", resp.StatusCode)
	}
	if _, err := store.UserByID(ctx, u.ID); !errors.Is(err, theauth.ErrStorageNotFound) {
		t.Fatalf("user must be gone: %v", err)
	}
	if _, err := store.TOTPSecretByUserID(ctx, u.ID); !errors.Is(err, theauth.ErrStorageNotFound) {
		t.Fatalf("totp secret must be gone: %v", err)
	}
	if _, _, err := testutil.ValidateSessionForTest(a, ctx, tok); err == nil {
		t.Fatal("session of a deleted user must not validate")
	}
	if _, err := store.UserByID(ctx, other.ID); err != nil {
		t.Fatalf("bystander must survive: %v", err)
	}
	if got := hook.deleted.Load(); got == nil || got.ID != u.ID || got.Email != "bye@lc.com" {
		t.Fatalf("OnAccountDeleted got %+v", got)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		events, _, err := a.QueryAudit(ctx, theauth.AuditQuery{Action: "account.deleted"})
		if err == nil && len(events) == 1 && events[0].TargetID == u.ID.String() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no account.deleted audit event: %v %v", events, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSelfServiceAccountDeletionNeedsRecentAuth(t *testing.T) {
	a, store := lcAuth(t, func(c *theauth.Config) {
		c.AccountDeletion = &theauth.AccountDeletionConfig{RecentAuthMaxAge: time.Millisecond}
	})
	ctx := context.Background()
	u := lcSignup(t, a, "stale@lc.com")
	tok, err := lcSignin(a, "stale@lc.com", lcPassword)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	srv := httptest.NewServer(mountedHandler(a))
	defer srv.Close()
	resp, body := authedDo(t, http.MethodDelete, srv.URL+"/account", tok, "")
	if resp.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte("recent_auth_required")) {
		t.Fatalf("stale session: %d %s", resp.StatusCode, body)
	}
	if _, err := store.UserByID(ctx, u.ID); err != nil {
		t.Fatalf("user must survive a refused delete: %v", err)
	}
}

func TestDeleteUserRefusesLastOrganizationOwner(t *testing.T) {
	a, store := lcAuth(t, func(c *theauth.Config) {
		c.Organizations = &theauth.OrganizationsConfig{}
	})
	ctx := context.Background()
	u := lcSignup(t, a, "owner@lc.com")
	if _, err := a.CreateOrganization(ctx, "Acme", "acme-lc", u.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteUser(ctx, u.ID); !errors.Is(err, theauth.ErrLastOwner) {
		t.Fatalf("err = %v, want ErrLastOwner", err)
	}
	if _, err := store.UserByID(ctx, u.ID); err != nil {
		t.Fatal("user must survive")
	}
	orgs, _ := a.ListUserOrganizations(ctx, u.ID)
	if err := a.RemoveOrganizationMember(ctx, orgs[0].ID, u.ID); err == nil {
		t.Fatal("setup: last owner removal should be refused too")
	}
}

func TestDeleteUserCascadesMemberships(t *testing.T) {
	a, store := lcAuth(t, func(c *theauth.Config) {
		c.Organizations = &theauth.OrganizationsConfig{}
	})
	ctx := context.Background()
	owner := lcSignup(t, a, "own2@lc.com")
	member := lcSignup(t, a, "mem2@lc.com")
	org, err := a.CreateOrganization(ctx, "Acme2", "acme-lc2", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddOrganizationMember(ctx, org.ID, member.ID, theauth.OrgRoleMember); err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteUser(ctx, member.ID); err != nil {
		t.Fatal(err)
	}
	members, err := store.OrganizationMembersByOrg(ctx, org.ID)
	if err != nil || len(members) != 1 || members[0].UserID != owner.ID {
		t.Fatalf("members after delete = %+v, %v", members, err)
	}
}

func lcPostJSON(t *testing.T, url string, body any, cookies ...*http.Cookie) (*http.Response, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

func lcCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestTrustedDeviceSkipsTOTPUntilPasswordChange(t *testing.T) {
	a, _ := lcAuth(t, func(c *theauth.Config) {
		c.TrustedDevices = &theauth.TrustedDevicesConfig{TTL: time.Hour}
	})
	ctx := context.Background()
	u := lcSignup(t, a, "trust@lc.com")
	codes := lcEnrollTOTP(t, a, u)
	srv := httptest.NewServer(mountedHandler(a))
	defer srv.Close()
	signin := func(cookies ...*http.Cookie) (*http.Response, string) {
		resp, body := lcPostJSON(t, srv.URL+"/auth/email-password/signin",
			map[string]string{"email": "trust@lc.com", "password": lcPassword}, cookies...)
		var out struct {
			Step string `json:"step"`
		}
		_ = json.Unmarshal(body, &out)
		return resp, out.Step
	}

	// First sign-in needs the second factor; remember the device on the way.
	resp, step := signin()
	if step != "totp_required" {
		t.Fatalf("first step = %q", step)
	}
	pending := lcCookie(resp, "theauth_session")
	vresp, vbody := lcPostJSON(t, srv.URL+"/auth/totp/recovery",
		map[string]any{"code": codes[0], "rememberDevice": true}, pending)
	if vresp.StatusCode != http.StatusOK {
		t.Fatalf("recovery verify = %d %s", vresp.StatusCode, vbody)
	}
	device := lcCookie(vresp, "theauth_trusted_device")
	if device == nil || !device.HttpOnly {
		t.Fatalf("trusted device cookie missing or not HttpOnly: %+v", device)
	}
	full := lcCookie(vresp, "theauth_session")

	// Remembered device skips TOTP; an unknown or forged cookie does not.
	if _, step := signin(device); step != "full" {
		t.Fatalf("remembered device step = %q, want full", step)
	}
	if _, step := signin(); step != "totp_required" {
		t.Fatalf("no cookie step = %q, want totp_required", step)
	}
	forged := &http.Cookie{Name: device.Name, Value: device.Value + "x"}
	if _, step := signin(forged); step != "totp_required" {
		t.Fatalf("forged cookie step = %q, want totp_required", step)
	}

	// The device shows up in the list and the plain device token is not stored.
	list, err := a.ListTrustedDevices(ctx, u.ID)
	if err != nil || len(list) != 1 || list[0].DeviceLabel == "" {
		t.Fatalf("ListTrustedDevices = %+v, %v", list, err)
	}

	// Changing the password revokes trust.
	if _, err := a.ChangePassword(ctx, theauth.Session{UserID: u.ID}, lcPassword, "new-passphrase-after-change-9"); err != nil {
		t.Fatal(err)
	}
	resp2, vstep := lcPostJSON(t, srv.URL+"/auth/email-password/signin",
		map[string]string{"email": "trust@lc.com", "password": "new-passphrase-after-change-9"}, device)
	var out struct {
		Step string `json:"step"`
	}
	_ = json.Unmarshal(vstep, &out)
	if resp2.StatusCode != http.StatusOK || out.Step != "totp_required" {
		t.Fatalf("after password change: %d step %q, want totp_required", resp2.StatusCode, out.Step)
	}
	_ = full
}

func TestTrustedDeviceListAndRevokeEndpoints(t *testing.T) {
	a, _ := lcAuth(t, func(c *theauth.Config) {
		c.TrustedDevices = &theauth.TrustedDevicesConfig{}
	})
	u := lcSignup(t, a, "tdlist@lc.com")
	srv := httptest.NewServer(mountedHandler(a))
	defer srv.Close()
	codes := lcEnrollTOTP(t, a, u)
	sresp, _ := lcPostJSON(t, srv.URL+"/auth/email-password/signin",
		map[string]string{"email": "tdlist@lc.com", "password": lcPassword})
	vresp, vbody := lcPostJSON(t, srv.URL+"/auth/totp/recovery",
		map[string]any{"code": codes[0], "rememberDevice": true}, lcCookie(sresp, "theauth_session"))
	if lcCookie(vresp, "theauth_trusted_device") == nil {
		t.Fatalf("no trusted device cookie: %d %s", vresp.StatusCode, vbody)
	}
	tok := lcCookie(vresp, "theauth_session").Value

	resp, body := authedDo(t, http.MethodGet, srv.URL+"/auth/trusted-devices", tok, "")
	var list struct {
		Devices []struct {
			ID          string `json:"id"`
			DeviceLabel string `json:"deviceLabel"`
		} `json:"devices"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Devices) != 1 ||
		list.Devices[0].DeviceLabel == "" {
		t.Fatalf("list = %d %s", resp.StatusCode, body)
	}
	resp, _ = authedDo(t, http.MethodDelete, srv.URL+"/auth/trusted-devices/"+list.Devices[0].ID, tok, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d", resp.StatusCode)
	}
	resp, _ = authedDo(t, http.MethodDelete, srv.URL+"/auth/trusted-devices/"+list.Devices[0].ID, tok, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second revoke = %d, want 404", resp.StatusCode)
	}
}

func TestTrustedDevicesRequireTOTPAndCapability(t *testing.T) {
	_, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://x", TrustedDevices: &theauth.TrustedDevicesConfig{},
	})
	if err == nil {
		t.Fatal("TrustedDevices without TOTP must fail")
	}
}
