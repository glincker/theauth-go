# Use the SQLite Backend

`storage/sqlite` is a pure Go (`modernc.org/sqlite`, no cgo) adapter that runs on a `*sql.DB` you already own. It is its own Go module, so the SQLite driver is only pulled in when you import it.

```sh
go get github.com/glincker/theauth-go/storage/sqlite
```

## What it covers

| Capability | Status |
| --- | --- |
| Users, sessions, magic links, passwords (`CoreStorage`) | Implemented |
| OAuth accounts, WebAuthn, TOTP, audit log | Implemented |
| Session list, last seen, step-up, session links (`SessionManagementStorage`, `SessionLinkStorage`) | Implemented |
| API tokens and RFC 8628 device codes (`APITokenStorage`, `DeviceCodeStorage`) | Implemented |
| TOTP replay, user count, passkey rename, recovery codes (`TOTPReplayStorage`, `UserCountStorage`, `WebAuthnRenameStorage`, `RecoveryCodeStorage`) | Implemented |
| Shared login throttle (`Store.ThrottleStore`) | Implemented |
| Organizations, SAML, SCIM, RBAC | Not implemented, returns `ErrStorageMissingCapability` |
| OAuth authorization server storage | Not implemented |

Set it as `Config.CoreStorage`. Features that need a missing capability fail at `New` instead of at request time.

## Open the database

You open the database and own its pragmas. Foreign keys must be on for every connection, and `New` refuses a database where they are off (pass `AllowForeignKeysOff` to override, at the cost of `ON DELETE CASCADE`). Use WAL and a busy timeout when anything else writes to the file:

```go
db, err := sql.Open("sqlite",
    "file:app.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate")
```

Run the first `Ping` serially at startup: switching a fresh file to WAL needs an exclusive lock that parallel first connections can lose with `SQLITE_BUSY`. `_txlock=immediate` makes every transaction take the write lock up front, which avoids `SQLITE_BUSY` on read-then-write upgrades under contention.

## Standalone: let the package migrate

```go
import sqlitestore "github.com/glincker/theauth-go/storage/sqlite"

if err := sqlitestore.Migrate(ctx, db); err != nil { ... }
store, err := sqlitestore.New(db)
```

`Migrate` records applied versions in `theauth_schema_migrations`. Each step runs under `BEGIN IMMEDIATE` together with its ledger row, so replicas starting at once serialize and a failed step leaves nothing half applied.

## Hosted: fold the SQL into your own migrator

`Migrations()` returns an `fs.FS` of numbered, forward-only `.sql` files (`0001_core.sql`, `0002_oauth_accounts.sql`, ...). Copy or embed them into your own numbered history, keeping their order, and do not call `Migrate`:

```go
files, _ := fs.Glob(sqlitestore.Migrations(), "*.sql")
```

If you use a custom prefix, `RenderMigrations(sqlitestore.WithTablePrefix("auth_"))` returns the same steps with the prefix applied. Never edit a step you have already shipped; later versions of this package only add files.

## Table prefix

Tables default to the `theauth_` prefix so they cannot collide with host tables. Pass the same `WithTablePrefix` option to `Migrate`, `RenderMigrations` and `New`. A prefix must match `[A-Za-z_][A-Za-z0-9_]*`.

## Expiry sweeps

Expired rows are not removed on read. Call `SweepExpired` from a host ticker:

```go
go func() {
    for range time.Tick(15 * time.Minute) {
        if _, err := store.SweepExpired(ctx, time.Now()); err != nil {
            slog.Error("auth sweep failed", "err", err)
        }
    }
}()
```

It deletes sessions, magic links and password reset tokens whose expiry has passed, in one transaction, and reports the counts.

## Shared login throttle

`store.ThrottleStore()` returns a `LoginThrottleStore` backed by the same database, so several processes share failure counters. It also implements `LoginThrottleCASStore`: the limiter re-reads and retries when another process changed an entry first, instead of overwriting it, so no failure is lost. Entries are not removed on read; call `ThrottleStore().SweepExpired(ctx, time.Now())` from the same ticker as `SweepExpired`.

```go
Config.LoginThrottle = &theauth.LoginThrottleConfig{Store: store.ThrottleStore()}
```

## Upgrading

Migrations `0006` to `0008` add session columns and tables (`last_seen_at`, `elevated_until`, `credential_id`, session links), API tokens, device codes, the TOTP step table and the throttle table. Existing sessions read back with a zero `LastSeenAt`. Run `Migrate` (or fold the new files into your migrator) before deploying.

## Behavior notes

- Email uniqueness is case-insensitive (`COLLATE NOCASE`, ASCII folding). A duplicate returns the driver's constraint error wrapped with context.
- IDs are stored as 26 character ULID text, timestamps as UTC unix microseconds.
- Consuming a magic link, reset token or session link, and claiming a device code, is one `UPDATE ... RETURNING`, so concurrent consumers produce exactly one winner. `AdvanceTOTPStep` is one conditional upsert.
- Audit rows carry no foreign keys: the log is append-only and survives deletion of the user it describes.
- `UpdateWebAuthnSignCount` returns `ErrReplayDetected` for a non-increasing count.
