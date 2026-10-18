# CreateUser

`(*TheAuth).CreateUser` creates a user row for an identity you already manage, for example when your own identity provider owns sign-in and agents or API tokens need a user to belong to. It mirrors `user.create` in the TypeScript SDK.

```go
u, err := a.CreateUser(ctx, theauth.CreateUserInput{
    Email: "Ada@Example.com", // validated, stored as ada@example.com
    Name:  "Ada",             // optional, at most 256 bytes
    ID:    myULID,            // optional, zero value generates one
})
```

## Behavior

- The email is normalized with `NormalizeEmail` (trim, lowercase, NFKC when `Config.EmailNFKC` is set) and must be a bare address of at most 320 characters.
- Idempotent on the normalized email: when the user exists and `ID` is zero or equal to the stored ID, the stored user is returned unchanged. Name is never updated.
- It sends no email and creates no password, passkey or session. `LifecycleHooks.OnSignup` does not fire.
- A newly created user emits a `user.created` audit event carrying a pseudonymous `email_ref`, not the address.
- Two concurrent calls with the same email yield one user and no error for the loser. In one process a mutex serializes the check and insert. Across processes the storage unique email constraint decides, and the loser re-reads the winner's row.
- Works on every storage backend through the existing `Storage` interface.

## What a created user can and cannot do

A user from `CreateUser` has no credential. It can sign in only through a method you add yourself: a passkey registered by a trusted flow, an OAuth link, or a password reset email flow if you configure one. It cannot sign in with a password, and no setup token can give it one.

`Config.Bootstrap` counts users. Once any user exists, including one from `CreateUser`, the gate is closed: password signup returns `SIGNUP_CLOSED` (unless `OpenSignupAfterFirstUser` is set, and then it needs no token), the setup token is cleared, and a restart issues no new token. Signup for the seeded address is therefore refused with `SIGNUP_CLOSED`, not with an email-taken error, and the setup token does not set a first password on an existing user. This is deliberate: it keeps the token from taking over an account that someone else created or linked. If Bootstrap is your only sign-in path, create the first admin with signup and the setup token, not with `CreateUser`.

## Errors

The returned error is a `*UserError` with a `Code` using the TypeScript names. Match with `errors.Is`:

| Sentinel | Code | When |
| --- | --- | --- |
| `ErrUserInvalidInput` | `USER_INVALID_INPUT` | Bad email, or name over 256 bytes. |
| `ErrUserEmailConflict` | `USER_EMAIL_CONFLICT` | The email exists under a different ID than the one requested. |
| `ErrUserIDConflict` | `USER_ID_CONFLICT` | The requested ID belongs to a different email. |

```go
_, err := a.CreateUser(ctx, in)
if errors.Is(err, theauth.ErrUserEmailConflict) {
    // the email is already tied to another user id
}
```
