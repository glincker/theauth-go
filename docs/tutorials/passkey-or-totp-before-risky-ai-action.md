# Require a passkey or TOTP before a risky AI action

An AI assistant asks your app to refund an order or delete records on a user's behalf, and a session that signed in with a password an hour ago is thin evidence that the person is still there.

In this tutorial you guard an endpoint so it needs a recent proof and a second factor, passkey or TOTP, recorded on the session. A user who only has a password gets a 403 until they step up. Then it goes through.

## Prerequisites

- Go 1.25 or newer.
- The memory, Postgres, MySQL or SQLite store. They all implement the session auth record.
- An authenticator app, or a passkey if you use WebAuthn.

```sh
go get github.com/glincker/theauth-go/v2@latest
```

Recording `amr` and `auth_time` on sessions needs v2.11.0 or later.

## How the session remembers

Each interactive sign in writes `Session.AuthMethods`, an RFC 8176 style list, and `Session.AuthTime`. A password gives `["pwd"]`. A device bound passkey gives `["hwk"]`, a synced passkey `["swk"]`. Password then TOTP gives `["pwd","otp","mfa"]`. The authorization server uses the same record for the `amr`, `acr` and `auth_time` claims, so a resource server asking for step-up sees what actually happened.

Magic links, social sign in and SAML record `email`, `fed` and `sso`. Those are never mistaken for `otp` or `hwk`.

## 1. Start from the TOTP example

[`examples/totp-stepup`](https://github.com/glincker/theauth-go/tree/main/examples/totp-stepup) mounts the full `/auth` route set with TOTP enabled and serves a small test page. The core of it is this.

```go
func main() {
	baseURL := envOr("BASE_URL", "http://localhost:8080")
	key := []byte(envOr("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")) // 32 bytes; rotate via your secrets manager in prod

	a, err := theauth.New(theauth.Config{
		Storage:       memory.New(),
		BaseURL:       baseURL,
		SecureCookie:  false,
		EncryptionKey: key,
		TOTP:          &theauth.TOTPConfig{Issuer: "TheAuth TOTP Demo"},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	r := chi.NewRouter()
	a.Mount(r)
	r.Get("/", indexHandler)
	r.Method(http.MethodPost, "/api/refund", approve(a))

	slog.Info("listening", "addr", ":8080", "baseURL", baseURL)
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
```

(The `/api/refund` route is my addition, covered in the next step.)

For the passkey version, [`examples/webauthn-passkey`](https://github.com/glincker/theauth-go/tree/main/examples/webauthn-passkey) configures `WebAuthn` the same way. Browsers allow WebAuthn only on `localhost` or HTTPS.

## 2. Guard the risky endpoint

The `r.Method(http.MethodPost, "/api/refund", approve(a))` line in step 1 is the one I added to the example.

The handler combines two checks. `RequireRecentAuth` returns 403 unless the user signed in or stepped up in the last five minutes. `HasAnyMethod` then asks for a hardware key passkey or TOTP in the session record.

```go
func approve(a *theauth.TheAuth) http.Handler {
	return a.RequireRecentAuth(5 * time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := theauth.SessionFromContext(r.Context())
		if !sess.HasAnyMethod(theauth.AMRHardwareKey, theauth.AMROTP) {
			http.Error(w, "step-up required", http.StatusForbidden) // send the user to /auth/step-up
			return
		}
		// proceed with the approval
		_, _ = w.Write([]byte("refund approved\n"))
	}))
}
```

## 3. Run it and step up

Start the server with `go run .`, then drive it with `curl` and a cookie jar. Sign up, begin and finish TOTP enrollment (enter the secret in your authenticator app), then call the endpoint with the password session:

```sh
curl -b jar -X POST localhost:8080/api/refund
```

```text
step-up required
 [403]
```

Now step up with a current code:

```sh
curl -b jar -X POST localhost:8080/auth/step-up \
  -H 'Content-Type: application/json' \
  -d '{"method":"totp","code":"123456"}'
```

```text
{"elevatedUntil":"2026-10-16T19:02:16.082259-05:00"}
 [200]
```

And the refund goes through:

```text
refund approved
 [200]
```

(The `123456` is a placeholder. Use the code your app shows.)

## What happened

`POST /auth/step-up` verified the code, raised the session for `Config.StepUpTTL`, and appended `otp` and `mfa` to the session record in one step. Before that the record was just `["pwd"]`, so `HasAnyMethod` failed. A step-up with a method already proved, such as the password again, only moves `AuthTime` forward. Method values for the request body are `password`, `totp` and `passkey`; the passkey path begins at `POST /auth/step-up/passkey/begin`.

If your host runs its own second factor, call `TheAuth.RecordSessionAuth(ctx, sess, theauth.AMROTP, theauth.AMRMFA)` after you verify it. It updates the session and bumps `AuthTime`.

## What session links cannot do

Only interactive sign ins record anything. Sessions from session links, `IssueSessionByUserID`, rows written straight to storage, and sessions from before an upgrade carry no `AuthMethods` and no `AuthTime`. They never satisfy a `HasMethod` check. The integration test [`session_auth_methods_test.go`](https://github.com/glincker/theauth-go/blob/main/integration/session_auth_methods_test.go) checks that each of those paths fails a passkey, TOTP, `mfa` or password requirement. If one of them completes a TOTP step-up, it records `["otp"]` alone: no `pwd`, no `mfa`.

Device codes, API tokens and OAuth token exchange create no browser session, so there is nothing to confuse.

## Limits

- This guards your own HTTP endpoints. An agent holding an OAuth token is not a browser session. For that, request `acr_values` on the authorize request, or gate the tool call itself.
- A passkey alone never records `mfa`.
- Everything above I ran with TOTP. I did not run the passkey path here, since it needs a browser authenticator.
- Old sessions have no record until the user signs in again, and they behave as before.

## Next

- [Sign-in methods and step-up reference](../session-auth-methods.md)
- [TOTP guide](https://docs.theauth.dev/go/guides/totp)
- [Passkeys guide](https://docs.theauth.dev/go/guides/webauthn-passkeys)
- [Deny risky actions for AI agents with IAM policies](deny-risky-ai-agent-actions-with-iam-policies.md)
