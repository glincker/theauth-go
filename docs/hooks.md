# Lifecycle hooks

`Config.LifecycleHooks` lets a host react to authentication events without wrapping every route. All fields are optional. A runnable demo lives in [`examples/hooks`](../examples/hooks).

| Hook | Fires |
| --- | --- |
| `OnSignup(ctx, user, method)` | A user is created: password, magic link, OAuth callback, SAML, or a user's first passkey. |
| `OnSignin(ctx, user, session)` | A sign-in completes: password (no second factor), the TOTP or recovery-code step that finishes a password sign-in, magic link, OAuth callback, passkey login, SAML. Not for the pending second-factor session, step-up, or session rotation. |
| `OnPasswordChange(ctx, user)` | Password reset, change, or admin reset. |
| `OnMFAEnabled(ctx, user, kind)` | TOTP enrollment is confirmed (`MFAKindTOTP`). Recovery codes are created in that same step. Passkeys are a single-factor sign-in method here, so they do not fire it. `MFAKindWebAuthn` and `MFAKindRecoveryCodes` are reserved. |
| `OnOrgSwitch(ctx, user, orgID)` | `SetActiveOrganization`, including clearing it (empty `orgID`). |
| `OnTokenIssued(ctx, claims)` | Before an OAuth access token is signed. Can add claims and can fail issuance. |

The `otp` package proves control of a destination and issues no session, so it has no hook.

## Errors and panics

`OnSignup`, `OnSignin`, `OnPasswordChange`, `OnMFAEnabled` and `OnOrgSwitch` run after the action committed. The user row, the session or the new password hash already exists, and undoing it safely would need a coordinated storage transaction. They are therefore observe-only: a returned error is logged at Warn level and does not fail the request. A panic is recovered and logged.

To get alerted instead of only logging, set `OnHookError`:

```go
LifecycleHooks: &theauth.LifecycleHooks{
    OnSignup: provisionTenant,
    OnHookError: func(ctx context.Context, hook string, err error) {
        metrics.HookFailures.WithLabelValues(hook).Inc()
    },
}
```

`OnHookError` receives every hook error and every recovered panic (wrapped in an error). It runs synchronously, so keep it fast. A panic inside it is recovered.

## Refusing a signup or sign-in

There is no veto on an after-the-fact hook. To block a signup or sign-in before it commits, gate it where the identity is known up front: wrap the mounted route, or check the address before calling the library.
