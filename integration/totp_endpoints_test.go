package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/integration/internal/testutil"
	"github.com/pquerna/otp/totp"
)

func authedDo(t *testing.T, method, url, token, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "theauth_session", Value: token})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestTOTPStatusRegenerateAndDeleteSlashForms(t *testing.T) {
	a, _, _ := newEventAuth(t)
	ctx := context.Background()
	u, _, err := testutil.SignupWithPasswordForTest(a, ctx, "ep@h.com", "twelve-chars-min-pw")
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := testutil.IssueSessionForTest(a, ctx, *u, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(t, a)

	resp, body := authedDo(t, http.MethodGet, srv.URL+"/auth/totp", tok, "")
	var st struct {
		Enrolled  bool `json:"enrolled"`
		Remaining int  `json:"recoveryCodesRemaining"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &st) != nil || st.Enrolled || st.Remaining != 0 {
		t.Fatalf("status before enroll: %d %s", resp.StatusCode, body)
	}
	if resp, _ = authedDo(t, http.MethodPost, srv.URL+"/auth/totp/recovery-codes", tok, ""); resp.StatusCode != http.StatusConflict {
		t.Fatalf("regenerate before enroll: want 409 got %d", resp.StatusCode)
	}

	enr, err := testutil.BeginTOTPEnrollmentForTest(a, ctx, u.ID, u.Email)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(enr.Secret, time.Now())
	codes, err := testutil.FinishTOTPEnrollmentForTest(a, ctx, u.ID, enr.EnrollmentID, code)
	if err != nil {
		t.Fatal(err)
	}

	_, body = authedDo(t, http.MethodGet, srv.URL+"/auth/totp", tok, "")
	if err := json.Unmarshal(body, &st); err != nil || !st.Enrolled || st.Remaining != len(codes) {
		t.Fatalf("status after enroll: %s", body)
	}

	resp, body = authedDo(t, http.MethodPost, srv.URL+"/auth/totp/recovery-codes", tok, "")
	var regen struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &regen) != nil || len(regen.RecoveryCodes) != len(codes) {
		t.Fatalf("regenerate: %d %s", resp.StatusCode, body)
	}
	pend, _, _ := testutil.IssuePending2FAForTest(a, ctx, u.ID, "ua", "127.0.0.1")
	if _, _, err := testutil.ConsumeRecoveryCodeForTest(a, ctx, pend, codes[0]); err == nil {
		t.Fatal("old recovery code must be invalid after regeneration")
	}
	pend2, _, _ := testutil.IssuePending2FAForTest(a, ctx, u.ID, "ua", "127.0.0.1")
	if _, _, err := testutil.ConsumeRecoveryCodeForTest(a, ctx, pend2, regen.RecoveryCodes[0]); err != nil {
		t.Fatalf("new recovery code must work: %v", err)
	}

	for _, path := range []string{"/auth/totp", "/auth/totp/"} {
		if resp, _ = authedDo(t, http.MethodDelete, srv.URL+path, tok, ""); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE %s: got %d", path, resp.StatusCode)
		}
	}
}
