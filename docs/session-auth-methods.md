# Sign-in methods and step-up

A session records how its user proved who they are. `Session.AuthMethods` lists the proofs in the order they happened, as [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176) authentication method references, and `Session.AuthTime` is when the last one happened. The authorization server reads the same record for the `amr`, `acr` and `auth_time` claims, so a resource server that asks for step-up (RFC 9470) sees what really happened instead of a fixed `["pwd"]`.

## What each sign-in records

| Sign-in | `AuthMethods` | Notes |
| --- | --- | --- |
| Email and password | `["pwd"]` | Also after a password change (the fresh session) |
| Magic link, emailed code | `["email"]` | Not an RFC 8176 value; theauth specific |
| Passkey (WebAuthn), device bound | `["hwk"]` | Credential is not backup eligible, so the key lives in one authenticator |
| Passkey (WebAuthn), synced | `["swk"]` | Credential is backup eligible (iCloud Keychain, Google Password Manager): a software secured key |
| Social OAuth (GitHub, Google, ...) | `["fed"]` | Not an RFC 8176 value; theauth specific |
| SAML single sign-on | `["sso"]` | Not an RFC 8176 value; theauth specific |
| Password, then TOTP or recovery code | `["pwd","otp","mfa"]` | The pending session starts as `["pwd"]`; completing the second factor appends `otp` and `mfa` |
| Step-up with a method not yet proved | previous methods plus the new one and `mfa` | Passkey adds `hwk` or `swk`, TOTP adds `otp`, password adds `pwd` |
| Step-up with a method already proved | unchanged | `AuthTime` still moves forward |

`mfa` means two or more distinct factors were proved. Recovery codes count as `otp`. The theauth specific values (`email`, `fed`, `sso`) are chosen so they never satisfy a requirement for a registered value: a policy that asks for `otp` or `hwk` is not met by a magic link or SSO login. Use `SessionAMR` (below) if your identity provider asserts a stronger method and you want to say so.

A passkey login also records `user` only when the authenticator set the user verified flag in that assertion. A passkey alone never records `mfa`, and nothing stronger than what happened is ever recorded.

Only interactive sign-ins record anything. Sessions from session links, `IssueSessionByUserID`, rows written straight to storage, and sessions that existed before the upgrade carry no `AuthMethods` and no `AuthTime`, so they never satisfy a `HasMethod` check. Device codes, API tokens and OAuth refresh or token exchange create no browser session. If such a session completes a step-up it records exactly the method proved (a TOTP step-up on a session link gives `["otp"]`, no `pwd`, no `mfa`).

Rotating a session (`RotateSession`) keeps the record and the original `AuthTime`. Sessions minted from a session link carry no record.

## Reading the record

```go
sess, ok := theauth.SessionFromContext(r.Context())
if !ok {
	return
}

sess.AuthMethods              // []string{"pwd", "otp", "mfa"}
sess.AuthTime                 // when the last proof happened
sess.HasMethod("hwk")         // one method
sess.HasAnyMethod("hwk", "otp") // passkey or TOTP
sess.HasAllMethods("pwd", "mfa")
```

The record lives on the `Session` value your code reads (`Session.AuthMethods`, `Session.AuthTime` and the `HasMethod` helpers). A host that marshals that value sees `authMethods` and `authTime` in the JSON. The built-in `GET /auth/sessions` list returns device information only (id, device label, IP prefix, created, last seen, expiry and whether it is current), not the record.

## Requiring a method before a risky action

`HasMethod` tells you what the session did at some point. Pair it with `RequireRecentAuth` so the proof is also fresh:

```go
func approve(a *theauth.TheAuth) http.Handler {
	return a.RequireRecentAuth(5 * time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := theauth.SessionFromContext(r.Context())
		if !sess.HasAnyMethod(theauth.AMRHardwareKey, theauth.AMROTP) {
			http.Error(w, "step-up required", http.StatusForbidden) // send the user to /auth/step-up
			return
		}
		// proceed with the approval
	}))
}
```

`POST /auth/step-up` (or `TheAuth.StepUp`) verifies a password, TOTP code or passkey assertion, elevates the session for `Config.StepUpTTL` and appends the method to the record in one step. A host that runs its own second factor calls `TheAuth.RecordSessionAuth(ctx, sess, theauth.AMROTP, theauth.AMRMFA)` after it verifies the factor; it updates `sess` in place and bumps `AuthTime`.

## Authorization server claims

`/oauth/authorize` builds the authentication context from the session:

- `amr` is `Session.AuthMethods`.
- `acr` is derived from `amr` through `AuthorizationServerConfig.ACRValues` (default `urn:theauth:acr:1fa` for one method, `urn:theauth:acr:mfa` for `mfa` or two or more methods).
- `auth_time` is `Session.AuthTime`, or the later of sign-in and the latest step-up for sessions without a record.
- `max_age` and `acr_values` on the authorize request are checked against the same values, so a session that only signed in with a password is sent back to log in when `urn:theauth:acr:mfa` is requested.

`AuthorizationServerConfig.SessionAMR` still exists as an override. When it returns a non-empty list that list wins over the record; return nil to defer to it.

## Storage and upgrading

Recording needs the optional `theauth.SessionAuthStorage` capability (`AppendSessionAuthMethods`). The memory, Postgres, MySQL and SQLite stores implement it and persist the record on `CreateSession`; the append is one atomic step (a row lock in a transaction), so concurrent second factors never lose a method. A third party store that does not implement it keeps compiling and working: its sessions simply have no record.

Sessions that exist when you upgrade have no record (`AuthMethods` is nil, `AuthTime` is zero) and behave as before: the authorization server assumes `["pwd"]` and computes `auth_time` from `CreatedAt` and the last step-up. A legacy session that completes a step-up records only the method it proved.

| Backend | Migration | Columns on the sessions table |
| --- | --- | --- |
| Postgres | `0030_session_auth_methods` (up and down) | `auth_methods text[]`, `auth_time timestamptz`, both nullable |
| MySQL | `0029_session_auth_methods` | `auth_methods JSON`, `auth_time DATETIME(6)`, both NULL |
| SQLite | `0034_session_auth_methods` | `auth_methods TEXT` (JSON array), `auth_time INTEGER` (unix microseconds), both NULL |
| Memory | none | fields on the stored session |

Run `Migrate` for your backend before deploying; the columns are additive and old binaries ignore them.
