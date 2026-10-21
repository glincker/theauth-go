# Storage capabilities by backend

theauth splits persistence into small capability interfaces. `New` checks the ones your `Config` needs and fails at startup if the store lacks one, so you find out when the process boots, not on a request. This page lists what each bundled backend implements and which migration adds it.

The cells were derived from the method sets of `memory.Store`, `sqlite.Store`, `postgres.Store` and `mysql.Store` and from the migration directories, not from the README. "Yes" means the type has every method of the interface. A number is the migration that creates the tables (SQLite files are named `0001_core.sql` and so on; Postgres and MySQL use `NNNN_name.up.sql`). The memory store keeps everything in process and has no migrations.

If you write your own backend, run the matching suite from `storagetest` against it.

## Core and sign-in

| Capability | Interface | memory | sqlite | postgres | mysql |
| --- | --- | --- | --- | --- | --- |
| Users, sessions, magic links | `CoreStorage` | Yes | Yes (0001) | Yes (0001) | Yes (0001) |
| Passwords | `PasswordStorage` | Yes | Yes (0001) | Yes (0002) | Yes (0002) |
| Social OAuth accounts | `OAuthAccountStorage` | Yes | Yes (0002) | Yes (0003) | Yes (0003) |
| Passkeys | `WebAuthnStorage`, `WebAuthnRenameStorage` | Yes | Yes (0003) | Yes (0004, 0017) | Yes (0004, 0017) |
| TOTP and recovery codes | `TOTPStorage`, `RecoveryCodeStorage` | Yes | Yes (0004) | Yes (0005) | Yes (0005) |
| TOTP replay guard, user count | `TOTPReplayStorage`, `UserCountStorage` | Yes | Yes (0008) | Yes (0018) | Yes (0018) |
| Session management (list, revoke, step-up) | `SessionManagementStorage` | Yes | Yes (0006) | Yes (0018) | Yes (0018) |
| Session links | `SessionLinkStorage` | Yes | Yes (0006) | Yes (0018) | Yes (0018) |
| Session auth methods (`amr`, `auth_time`) | `SessionAuthStorage` | Yes | Yes (0034) | Yes (0030) | Yes (0029) |
| Account state, account delete, trusted devices | `AccountStateStorage`, `AccountDeleteStorage`, `TrustedDeviceStorage` | Yes | Yes (0010) | Yes (0022) | Yes (0022) |
| Login throttle (shared compare and swap) | `LoginThrottleCASStore` | Yes | Yes (0008) | Yes (0018) | Yes (0018) |
| Bulk user import | `ImportUserStorage` | Yes | Yes | Yes | Yes |

## Enterprise and audit

| Capability | Interface | memory | sqlite | postgres | mysql |
| --- | --- | --- | --- | --- | --- |
| Organizations | `OrganizationStorage` | Yes | Yes (0013) | Yes (0006) | Yes (0006) |
| SAML | `SAMLStorage` | Yes | Yes (0014) | Yes (0007) | Yes (0007) |
| SCIM | `SCIMStorage` | Yes | Yes (0015) | Yes (0008) | Yes (0008) |
| RBAC | `RBACStorage` | Yes | Yes (0016) | Yes (0009) | Yes (0009) |
| Audit log | `AuditStorage` | Yes | Yes (0005) | Yes (0010) | Yes (0010) |
| Audit write order (`recorded_at_us`, `event`, `Order`, `c1.` cursors) | `storagetest.AuditOrderCapable` (`AuditOrderSupported() bool`) | Yes | Yes (0036) | Yes (0032) | Yes (0031) |
| Audit provenance filter (`AuditQuery.Provenance`) | `storagetest.AuditProvenanceCapable` (`AuditProvenanceSupported() bool`) | Yes | Yes (0017) | Yes (0028) | Yes (0027) |
| Rotating audit pseudonyms | `AuditPseudonymRotator` | Yes | Yes (0038) | Yes (0035) | Yes (0033) |
| Audit hash chain | `VerifyAuditChain`, `ChainSupported` | Yes (ring buffer, see below) | Yes (0017) | Yes (0028) | Yes (0027) |
| Shared signals store | `SignalsStore()` | Use `signals.NewMemoryStore` | Yes (0012) | Yes (0026) | No |
| API tokens | `APITokenStorage` | Yes | Yes (0007) | Yes (0018) | Yes (0018) |
| Agent id on API tokens | `APITokenAgentStorage` | Yes | Yes (0018) | Yes (0027) | Yes (0026) |
| Device codes (API token device grant) | `DeviceCodeStorage`, `DeviceCodeLister` | Yes | Yes (0007) | Yes (0018) | Yes (0018) |
| Device identity (join tokens, enrolled devices) | `DeviceIdentityStorage` | Yes | Yes (0011, 0039) | Yes (0024, 0036) | Yes (0024, 0036) |
| Token vault credentials (`tokenvault` package) | `TokenVaultStorage` | Yes | No | No | No |
| Agent tool approvals (single use, used by `toolguard.NewStorageApprovals`) | `ToolApprovalStorage` | Yes | Yes (0019) | Yes (0029) | Yes (0028) |
| Approvals inbox and specific denial codes (get, list, deny; used by the `approvals` package and `StorageApprovals.Spend`) | `ToolApprovalAdminStorage` | Yes | Yes (0037) | Yes (0034) | Yes (0032) |
| Approval expiry marking (one audit row and event per expiry) | `ToolApprovalExpiryStorage` | Yes | Yes (0037) | Yes (0034) | Yes (0032) |

Audit write order is a flag, not an interface: a store declares it by returning true from `AuditOrderSupported()`. It means the store assigns `AuditEvent.RecordedAtUs` (microseconds, strictly increasing per chain key, a caller value is ignored), stores and filters `AuditEvent.Event` (nullable, empty on old rows), serves `AuditQuery.Order` (`asc` or `desc`, default `desc`) and pages with the opaque `c1.` keyset cursor on `(recorded_at_us, id)`. Neither new column is part of the audit chain hash, so chains written before keep verifying. Cursors from before this existed keep working for descending reads. `storagetest.RunAudit` runs the write order cases for stores that declare the flag and skips them with a message for the rest.

MySQL migration `0031_audit_write_order` (up only, like every MySQL migration) adds `audit_events.recorded_at_us BIGINT` and `event VARCHAR(255)`, a `recorded_at_us` column on `theauth_audit_chain_heads`, and three keyset indexes: `(recorded_at_us, id)`, `(organization_id, recorded_at_us, id)` and `(event, recorded_at_us, id)`. Existing rows are backfilled in the migration: `recorded_at_us` from `created_at` read as UTC (independent of the session time zone) and `event` from the action table in `internal/audit/events.go`, with unmapped actions left NULL. The column default uses an expression, so it needs MySQL 8.0.13 or later. `InsertAuditEvents` stamps `recorded_at_us` while it holds the `FOR UPDATE` lock on the chain head row, as `max(now, head stamp + 1)`, so stamps are strictly increasing per organization (and for the global chain) across processes. On a very large `audit_events` table, run the backfill and index builds with your own online tooling before `Migrate`, since the embedded statements scan the table once each.

Postgres migration 0032 (`audit_write_order`) adds nullable `recorded_at_us bigint` and `event text` to `audit_events`, a `recorded_at_us` high-water column on `theauth_audit_chain_heads`, and keyset indexes on `(recorded_at_us, id)`, `(organization_id, recorded_at_us, id)` and `(event, recorded_at_us, id)`. The writer assigns `recorded_at_us` inside the append transaction while it holds the chain head row lock: `max(now in microseconds, head stamp + 1, process counter + 1)`, so the stamp is strictly increasing per chain key and a caller supplied value is ignored. The migration backfills `recorded_at_us` from `created_at` in microseconds and `event` from the action mapping (actions without a shared event stay NULL). The column default stamps rows inserted by an older binary during a rolling deploy. Neither column is hashed, so chains written before 0032 verify unchanged. On a very large `audit_events` table you can run the backfill `UPDATE` in batches and create the indexes with `CREATE INDEX CONCURRENTLY` yourself before running `Migrate`, then record the version in `theauth_schema_migrations`.

The audit hash chain is what `VerifyAuditChain` and the `audit/checkpoint` package read. All four stores use the same row format (`internal/audit` `BuildChainEntry`) and the same verifier. A store that keeps no chain returns an explicit unsupported result, never a pass.

The memory store chains in process. Its audit log is a ring buffer of 10000 rows, so on a busy process the oldest rows are evicted. Verification then anchors on the first retained row of each chain and checks every later link, and eviction is not reported as a break. The pseudonym secret lives in process memory and is lost on restart, so use a SQL store where the chain must outlive the process.

### Head checkpoints (tail truncation)

A verifier that walks rows cannot see rows cut off the end of a chain, since every remaining row still links to the one before. `checkpoint.CreateHeadCheckpoint(ctx, store, checkpoint.HeadOptions{Signer: signer})` signs the last position of every chain (`chainKey`, `seq`, `hash`) with an Ed25519 key, the same `Signer` and public key a Merkle `Checkpoint` uses. Store the result where the log writer cannot rewrite it. Later, `checkpoint.CheckHeadCheckpoint(ctx, store, head, publicKey)` verifies the signature and then reports `chain_truncated` (a chain is shorter than signed or gone) or `head_mismatch` (the row at the signed seq has another hash). Rows and chains added after signing are fine. `VerifyHeadCheckpoint` checks only the signature, offline. Run `VerifyAuditChain` as well, since the head check looks only at the signed positions. When the chain has grown past the signed seq but the store no longer holds that row (the memory ring evicted it, or retention removed it), the check reports `head_not_retained`. That is not tampering and not proof of it, so check a newer head checkpoint instead.

Wire format: JSON `{version: 1, alg: "Ed25519", keyId, timestamp (ms), heads: [{chainKey, seq, hash}], signature}`, heads sorted by `chainKey`. The signature is base64url without padding over the bytes `theauth.audit.head.v1\n` followed by the canonical JSON (sorted keys, no whitespace) of `{version, alg, keyId, timestamp, heads}`. The TypeScript SDK verifies this object with `verifyGoHeadCheckpoint` (and `theauth audit verify-go --head`), so a TypeScript service can detect tail truncation of a Go chain given the signing public key.

The Postgres (0028) and MySQL (0027) chain migrations already exist, and a head checkpoint reads the chain through `QueryAuditEvents`, so no new migration is needed.

### Test vectors for other implementations

`internal/audit/testdata/chain-vectors.json` pins the Go chain hash (format `go-v1`, payload `v` 1) so another implementation can check itself without this library. Chain rows are exported as the JSON of `AuditEvent` (camelCase keys, `createdAt` as RFC 3339, `chainSeq`, `prevHash`, `hash`). The hashed bytes are not that JSON: they are built as follows.

1. Take the row's pseudonyms: `HMAC-SHA256(secret, "theauth.audit.pseudonym.v1:" + id)` in lowercase hex for the actor user id, subject, actor and approver ids, and `""` for an empty id. The actor session id is hashed raw.
2. Build a JSON object with these 21 keys in this exact order: `v`, `chainKey`, `seq`, `prev`, `id`, `org`, `actorUserPseudonym`, `actorSession`, `action`, `targetType`, `targetId`, `metadata`, `ip`, `userAgent`, `createdAt`, `subjectPseudonym`, `actorPseudonym`, `policyVersion`, `approverPseudonym`, `delegationChain`, `inputProvenance`. `v` is 1, `seq` and `createdAt` are JSON integers (`createdAt` is microseconds since the Unix epoch in UTC), `chainKey` and `org` are the organization id (empty for the global chain), `prev` is the previous row's hash (empty for seq 1), and every other value is a string. A missing value is `""`, never null.
3. `metadata`, `delegationChain` and `inputProvenance` are strings holding compact JSON text: object keys sorted, no whitespace, and `<`, `>`, `&`, U+2028 and U+2029 written as `<`, `>`, `&`, ` `, ` ` (Go `encoding/json`). Null or empty values become `{}`, `[]` and `{}`. The same escaping applies when that text is embedded in the outer object. Non-ASCII characters are otherwise written as raw UTF-8.
4. The hash is the lowercase hex SHA-256 of the object's bytes. Rows chain by `seq` 1, 2, 3 per `chainKey` and `prev` equal to the previous hash.

Each vector row carries the exact `payload` string next to its `hash`, so a failing verifier can compare bytes. Large `seq` values appear only inside `payload` and in the `hashOnly` rows. The `negative` vectors list the rows to hand a verifier and the `FirstBreak.Reason` it must return (`hash_mismatch`, `prev_hash_mismatch`, `seq_gap`, `pseudonym_mismatch`). Worked example, the first row of the `org-b-no-actors` chain, with the file's secret (bytes `00` to `1f`) not needed because no ids are pseudonymized:

```
{"v":1,"chainKey":"010000004V000000000000005G","seq":1,"prev":"","id":"010000004V000000000000000H","org":"010000004V000000000000005G","actorUserPseudonym":"","actorSession":"","action":"org.updated","targetType":"org","targetId":"b","metadata":"{\"plan\":\"pro\",\"seats\":5}","ip":"","userAgent":"","createdAt":0,"subjectPseudonym":"","actorPseudonym":"","policyVersion":"","approverPseudonym":"","delegationChain":"[]","inputProvenance":"{}"}
```

hashes to `382c15bdef785ddc66b146684db6490b5a1ab48ddc48b42a7d0f16fe49b5153e`. The tests never regenerate the file by default; `THEAUTH_UPDATE_VECTORS=1 go test ./internal/audit -run TestChainVectors` rewrites it after an intentional, versioned change.

## OAuth 2.1 authorization server

`OAuthServerStorage` is one interface that covers clients, authorization codes, refresh tokens, JWKS keys, agents and delegation grants. All four backends implement it. The rows below split it up so you can see where the migrations land.

| Capability | Interface or methods | memory | sqlite | postgres | mysql |
| --- | --- | --- | --- | --- | --- |
| Clients | `InsertOAuthClient` and friends | Yes | Yes (0020) | Yes (0011, 0025) | Yes (0011, 0025) |
| Authorization codes, replay revocation | `ConsumeAuthorizationCode`, `RevokeRefreshTokensByAuthCode` | Yes | Yes (0021) | Yes (0011) | Yes (0011) |
| Refresh tokens, family revocation | `InsertRefreshToken` and friends | Yes | Yes (0022) | Yes (0011) | Yes (0011) |
| Access token denylist (`AccessTokenRevocation`) | `DenyAccessToken`, `IsAccessTokenDenied` | Yes | Yes (0023) | Yes (0019) | Yes (0019) |
| JWKS keys | `InsertJWKSKey` and friends | Yes | Yes (0024) | Yes (0014, 0015) | Yes (0014) |
| Atomic JWKS rotation | `AtomicRotateJWKS` | No | Yes | Yes | No |
| Pushed authorization requests (RFC 9126) | `InsertPushedRequest`, `ConsumePushedRequest` | Yes | Yes (0025) | Yes (0016) | No |
| Opaque access tokens | `OpaqueTokenStorage` | Yes | Yes (0026) | Yes (0021) | Yes (0021) |
| Device authorization grant (RFC 8628) | `DeviceAuthorizationStorage` | Yes | Yes (0027) | Yes (0020) | Yes (0020) |
| Registration tokens | `RegistrationTokenStorage` | Yes | Yes (0028) | Yes (0020) | Yes (0020) |
| Agents and credentials | `InsertAgent` and friends | Yes | Yes (0030) | Yes (0012) | Yes (0012) |
| Agent expiry (`UpdateAgentExpiry`, `Agent.ExpiresAt`) | Part of `OAuthServerStorage` | Yes | Yes (0035) | Yes (0031) | Yes (0030) |
| Delegation grants | `InsertDelegationGrant` and friends | Yes | Yes (0031) | Yes (0013) | Yes (0013) |
| jwt-bearer `jti` cache | `JWTBearerStorage` | Yes | Yes (0032) | No | No |
| CIBA requests | `CIBAStorage` | Yes | Yes (0033) | Yes (0016) | No |
| CIBA served once | `BackchannelRedeemer` | Yes | Yes (0033) | Yes (0016) | No |

SQLite also has `0029_oauth_cascade_triggers`, which removes a client's codes and tokens when the client is deleted. Token policy, authorization context and OIDC client metadata (Postgres and MySQL migrations 0021, 0023 and 0025) are columns of the clients and codes tables that SQLite creates in 0020 to 0022.

## Notes

- MySQL has no CIBA storage and no pushed authorization requests. If you set `AuthorizationServerConfig.CIBA` or `PAR` on a backend without the interface, the endpoints are not mounted and `New` does not fail, so check the metadata document (`backchannel_authentication_endpoint`, `pushed_authorization_request_endpoint`) after startup. The MySQL migration list has no files for either.
- Postgres and MySQL have no `JWTBearerStorage`. The jwt-bearer grant still works: the server falls back to an in-process `jti` cache. That cache is per process and is lost on restart, so with several replicas a replayed assertion can be accepted by a different node inside its lifetime. Use a backend with the interface (SQLite or memory) or keep assertion lifetimes short.
- Without `BackchannelRedeemer` (MySQL has no CIBA at all), the server serializes redemption with an in-process lock, which does not hold across nodes.
- The memory audit chain lives in a 10000 row ring buffer and a per process secret. It detects edits to retained rows, not eviction or a restart. Use a SQL store where you need durable tamper evidence.
- Postgres migration 0033 (`delegation_live_unique`) replaces the full `UNIQUE (user_id, agent_id, resource)` on `delegation_grants` with a partial unique index on live rows (`revoked_at IS NULL`), as SQLite and memory already behave, so a grant can be re-issued after a revoke. Password hashes on Postgres live in `users.password_hash`; there is no separate password table. The shared `storagetest` contract passes on Postgres when `THEAUTH_PG_CONTRACT=1` and `THEAUTH_TEST_PG_DSN` are set (checked on PostgreSQL 14), but CI does not set them yet. The contract test resets the `public` schema, so point it at a scratch database.
- Postgres has two migrations numbered 0016 (`backchannel_requests` and `pushed_authorization_requests`). Both apply; the numbering is historical.
- MySQL session auth methods (0029) has a contract test (`storagetest.RunSessionAuthMethods` in `storage/mysql/mysql_caps_test.go`) that needs `THEAUTH_TEST_MYSQL_DSN`. It is not run by a plain `go test`: set `THEAUTH_MYSQL_CONTRACT=1` and `THEAUTH_TEST_MYSQL_DSN`. All MySQL suites (the full `storagetest.Run` contract, the capability suites, the audit chain, the kv adapter, the concurrent claim races and the 0034 upgrade test) passed against MySQL 8.4.11 on 2026-10-18, and CI repeats them on `mysql:8.4` in `.github/workflows/mysql-contract.yml`. This page was checked against that server. MariaDB and other MySQL versions have not been tested.
- Old SQLite schema. If a database has not run 0034, sessions still read and write without an auth record and recording one returns `ErrStorageMissingCapability`. If it has not run 0017, audit events are written in the old shape and are not chained. Run `Migrate` before you deploy.
- Consent tickets and rate limits are not part of the storage interfaces. They use `Config.Stores` (`kv.ReplayCache`, `kv.RateLimiter`, `kv.Cache`), which is in memory by default. The `kv/sqlkv` adapter runs on SQLite, Postgres and MySQL, and `kv/redis` is available too. See [pluggable-stores.md](pluggable-stores.md).

Per backend notes: [storage/sqlite/README.md](../storage/sqlite/README.md). For running the OAuth server on SQLite, see [mcp-oauth-sqlite.md](mcp-oauth-sqlite.md).

## Writing foreign key safe contract cases

Memory and SQLite do not enforce foreign keys by default, Postgres and MySQL do, so a `storagetest` case that references a row it never created passes on the first two and fails on the others. When a case sets an actor, owner, user, agent or OAuth client id, create that row first through the store's own API. Use the helpers in `storagetest/helpers.go`: `ensureUser` (users), `ensureOAuthClient` (clients, needed by authorization codes, refresh tokens and agents) and `ensureAgent` (delegation grants). Use a nil pointer instead where the schema allows it (for example `ActorUserID`). Never invent a random id for a column that has a foreign key. Create the rows inside the case or helper that needs them, using the subtest's own `t`.

## Migrations and the CLI

Postgres and MySQL keep a `theauth_schema_migrations` ledger and expose `Migrate(ctx, db)` plus a read only `Status(ctx, db)` that returns each embedded migration with its applied state and time (`MigrationStatus`). SQLite exposes `Migrate` and `RenderMigrations` from its own module. `theauth-go db status` and `theauth-go db migrate` wrap the Postgres and MySQL functions; SQLite is library only. See [cli.md](cli.md).
