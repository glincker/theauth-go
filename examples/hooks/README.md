# hooks

Wires every `Config.LifecycleHooks` callback to a log line so you can see when each one fires. Password sign-in with a TOTP second factor, in memory.

## Run

```bash
go run ./examples/hooks
```

Then drive the API (a cookie jar keeps the session):

```bash
curl -c jar -s -XPOST localhost:8080/auth/signup -d '{"email":"a@example.com","password":"twelve-chars-min"}'   # OnSignup
curl -c jar -s -XPOST localhost:8080/auth/signin -d '{"email":"a@example.com","password":"twelve-chars-min"}'   # OnSignin
```

TOTP enrollment (`/auth/totp/enroll/*`) fires `OnMFAEnabled`, and a sign-in held for a second factor fires `OnSignin` when `/auth/totp/verify` succeeds.

## Notes

- Hooks run after the action committed, so they are observe-only. A returned error or a panic is logged, passed to `OnHookError`, and does not fail the request.
- To refuse a signup or sign-in before it happens, gate it ahead of the library (wrap the route, or check the address first).
- `OnTokenIssued` is the one hook that can fail a request, because the token is not yet minted. It is set on the same `LifecycleHooks` struct and only matters when the authorization server is enabled.

`ENCRYPTION_KEY` (32 bytes) protects TOTP secrets at rest; the default is for local use only. See [`docs/hooks.md`](../../docs/hooks.md).
