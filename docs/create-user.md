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
