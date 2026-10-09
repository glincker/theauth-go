# Migrating from Keycloak to theauth-go

Move users, password hashes and social links out of a Keycloak realm without
forcing everyone to reset a password. Users sign in with their existing
password once, and that login upgrades their stored hash to Argon2id.

## What carries over

| Keycloak | theauth-go |
| --- | --- |
| Users (email, name, verified flag, attributes) | Users, attributes kept as metadata |
| Password credentials (`pbkdf2-sha256`, `pbkdf2-sha512`) | Legacy hash, verified then upgraded to Argon2id at first login |
| Federated identities (Google, GitHub, and so on) | OAuth accounts |
| OTP credentials | Not carried: the secret is not exportable, so these users re-enroll |
| Passwords with another algorithm (for example Argon2) | Password reset |
| Disabled users | Skipped, and the count is noted in the bundle |
| Roles, groups, client scopes, required actions | Not carried: recreate with organizations and RBAC |

## Steps

**1. Export the realm.** In the admin console: Realm settings, Action,
Partial export, include users. Or run `kc.sh export --realm NAME --users
realm_file`. You need the `users` array with credentials included.

**2. Convert to a bundle.**

```
theauth-migrate keycloak --export realm-export.json --output bundle.json
```

It prints how many users, passwords, OAuth accounts and MFA records it read.
Open `bundle.json`: the `notes` array lists every user that was skipped or
needs a reset, and why. Add `--force-password-reset` to drop every hash and
make everyone reset instead.

**3. Validate and dry-run.**

```
theauth-migrate validate --input bundle.json
theauth-migrate keycloak --input bundle.json --apply --storage postgres --dsn "$DSN" --dry-run
```

**4. Turn on legacy hash support.** For the migration window only:

```go
theauth.Config{
    // ...
    PasswordPolicy: theauth.PasswordPolicyConfig{AllowLegacyBcrypt: true},
}
```

The setting name says bcrypt for historical reasons. It covers bcrypt
(Auth0) and PBKDF2 (Keycloak). It also bounds work: a stored PBKDF2 hash with
more than 5,000,000 iterations is rejected.

**5. Apply.**

```
theauth-migrate keycloak --input bundle.json --apply --storage postgres --dsn "$DSN"
```

**6. Cut over, then close the window.** Users sign in with their old
password. The first successful login rewrites the hash as Argon2id. After
your active users have logged in (30 to 90 days is typical), set
`AllowLegacyBcrypt` back to false. Anyone who never logged in uses password
reset.

## Running both systems side by side

You do not have to move everyone at once. Apply the bundle, run theauth-go for
new sign-ups and migrated users, and keep Keycloak for apps you have not moved
yet. Re-run the export later to pick up users created in Keycloak since: the
applier skips users that already exist.

## Checked

`cmd/theauth-migrate/keycloak/reader_test.go` runs the whole path: a realm
export with real PBKDF2 credentials, conversion, apply into storage, sign-in
with the Keycloak password, and a second sign-in after the hash was upgraded
with legacy support off.
