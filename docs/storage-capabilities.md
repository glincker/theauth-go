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
| Audit hash chain | `VerifyAuditChain`, `ChainSupported` | No (reports unsupported) | Yes (0017) | Yes (0028) | Yes (0027) |
| Shared signals store | `SignalsStore()` | Use `signals.NewMemoryStore` | Yes (0012) | Yes (0026) | No |
| API tokens | `APITokenStorage` | Yes | Yes (0007) | Yes (0018) | Yes (0018) |
| Agent id on API tokens | `APITokenAgentStorage` | Yes | Yes (0018) | Yes (0027) | Yes (0026) |
| Device codes (API token device grant) | `DeviceCodeStorage`, `DeviceCodeLister` | Yes | Yes (0007) | Yes (0018) | Yes (0018) |
| Device identity (join tokens, enrolled devices) | `DeviceIdentityStorage` | Yes | Yes (0011) | Yes (0024) | Yes (0024) |
| Token vault credentials (`tokenvault` package) | `TokenVaultStorage` | Yes | No | No | No |
| Agent tool approvals (single use, used by `toolguard.NewStorageApprovals`) | `ToolApprovalStorage` | Yes | Yes (0019) | Yes (0029) | Yes (0028) |
| Approvals inbox (get, list, deny; used by the `approvals` package) | `ToolApprovalAdminStorage` | Yes | No | No | No |

The audit hash chain is what `VerifyAuditChain` and the `audit/checkpoint` package read. The memory store returns an explicit unsupported result, never a pass.

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
- The memory store has no hash-linked audit chain. `VerifyAuditChain` returns `ErrAuditChainUnsupported`. Do not use it where you need tamper evidence.
- Postgres has two migrations numbered 0016 (`backchannel_requests` and `pushed_authorization_requests`). Both apply; the numbering is historical.
- MySQL session auth methods (0029) has a contract test (`storagetest.RunSessionAuthMethods` in `storage/mysql/mysql_caps_test.go`) that needs `THEAUTH_TEST_MYSQL_DSN`. It is not run by a plain `go test`, and this page was not checked against a live MySQL server.
- Old SQLite schema. If a database has not run 0034, sessions still read and write without an auth record and recording one returns `ErrStorageMissingCapability`. If it has not run 0017, audit events are written in the old shape and are not chained. Run `Migrate` before you deploy.
- Consent tickets and rate limits are not part of the storage interfaces. They use `Config.Stores` (`kv.ReplayCache`, `kv.RateLimiter`, `kv.Cache`), which is in memory by default. The `kv/sqlkv` adapter runs on SQLite, Postgres and MySQL, and `kv/redis` is available too. See [pluggable-stores.md](pluggable-stores.md).

Per backend notes: [storage/sqlite/README.md](../storage/sqlite/README.md). For running the OAuth server on SQLite, see [mcp-oauth-sqlite.md](mcp-oauth-sqlite.md).
