// hooks is a runnable demo of Config.LifecycleHooks.
//
// It mounts the full /auth/* route set with TOTP enabled and wires every
// observe-only hook to a structured log line, so you can watch each one
// fire while you drive the API with curl:
//
//	POST /auth/signup        -> OnSignup(password), OnSignin is not fired
//	POST /auth/signin        -> OnSignin
//	POST /auth/totp/enroll/* -> OnMFAEnabled(totp) when enrollment is confirmed
//	POST /auth/totp/verify   -> OnSignin (the second factor completes the sign-in)
//
// Passkey login, SAML, magic link and OAuth callback fire OnSignin the same
// way; see the LifecycleHooks doc comment for the full list.
//
// Hooks run after the action committed, so they cannot veto it. A returned
// error is logged and reported to OnHookError, and the request still
// succeeds. Use OnHookError to alert instead of only logging.
package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

func main() {
	baseURL := envOr("BASE_URL", "http://localhost:8080")
	key := []byte(envOr("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")) // 32 bytes; local use only

	a, err := theauth.New(theauth.Config{
		Storage:       memory.New(),
		BaseURL:       baseURL,
		SecureCookie:  false,
		EncryptionKey: key,
		TOTP:          &theauth.TOTPConfig{Issuer: "TheAuth Hooks Demo"},
		LifecycleHooks: &theauth.LifecycleHooks{
			// Provision per-user resources here: a tenant row, a Stripe
			// customer, a welcome email. method says which credential path
			// created the account.
			OnSignup: func(ctx context.Context, u *theauth.User, method theauth.SignupMethod) error {
				slog.InfoContext(ctx, "hook: signup", "user", u.ID.String(), "method", string(method))
				return nil
			},
			// Fires once per completed sign-in, whatever the method. It does
			// not fire for the pending second-factor intermediate.
			OnSignin: func(ctx context.Context, u *theauth.User, s *theauth.Session) error {
				slog.InfoContext(ctx, "hook: signin", "user", u.ID.String(), "session", s.ID.String())
				return nil
			},
			OnPasswordChange: func(ctx context.Context, u *theauth.User) error {
				slog.InfoContext(ctx, "hook: password changed", "user", u.ID.String())
				return nil
			},
			OnMFAEnabled: func(ctx context.Context, u *theauth.User, kind theauth.MFAKind) error {
				slog.InfoContext(ctx, "hook: mfa enabled", "user", u.ID.String(), "kind", string(kind))
				// Returning an error here would be logged and reported to
				// OnHookError, but would not undo the enrollment.
				return nil
			},
			OnOrgSwitch: func(ctx context.Context, u *theauth.User, orgID string) error {
				slog.InfoContext(ctx, "hook: org switch", "user", u.ID.String(), "org", orgID)
				return nil
			},
			// OnHookError sees every hook error and recovered panic, in
			// addition to the default slog line. Send it to your alerting.
			OnHookError: func(ctx context.Context, hook string, err error) {
				slog.ErrorContext(ctx, "hook failed", "hook", hook, "err", err.Error())
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	r := chi.NewRouter()
	a.Mount(r)

	slog.Info("listening", "addr", ":8080", "baseURL", baseURL)
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
