package theauth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/glincker/theauth-go"
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
