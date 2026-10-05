# Capability Interfaces and Choosing a Storage Backend

theauth-go does not require one monolithic storage interface. Persistence is split into small capability interfaces in `storage_caps.go` and a few optional extensions. A backend implements the ones it can, and `New` checks that every feature you enabled has the capability it needs. A missing one fails at startup with `ErrStorageMissingCapability`, not on the first request.

## Three ways to supply storage

- `Config.Storage` takes the full `theauth.Storage`: users, sessions, magic links, passwords, OAuth accounts, WebAuthn, TOTP, organizations, SAML, SCIM, RBAC and audit. `memory`, `postgres` and `mysql` satisfy it.
- `Config.CoreStorage` takes `theauth.CoreStorage`: users, sessions, magic links and passwords only. Anything else the adapter also implements is detected by type assertion. The rest are stubs that return `ErrStorageMissingCapability`. `sqlite` is used this way.
- Optional extension interfaces are asserted against the storage you pass. If it implements one, the feature turns on. If not, the feature is off or degrades as noted below.

Set exactly one of `Storage` and `CoreStorage`.

## Capabilities and who implements them

Verified against the adapters in this repository. "Yes" means the adapter has the methods and, where the repo declares one, a compile-time assertion or a test for it.

| Capability | Interface | memory | sqlite | postgres | mysql |
|---|---|---|---|---|---|
| Users, sessions, magic links, passwords | `CoreStorage` | Yes | Yes | Yes | Yes |
| OAuth provider accounts | `OAuthAccountStorage` | Yes | Yes | Yes | Yes |
| WebAuthn passkeys | `WebAuthnStorage` | Yes | Yes | Yes | Yes |
| TOTP and recovery codes | `TOTPStorage` | Yes | Yes | Yes | Yes |
| Audit log | `AuditStorage` | Yes | Yes | Yes | Yes |
| User count (first-run `Bootstrap`) | `UserCountStorage` | Yes | Yes | Yes | Yes |
| Passkey rename | `WebAuthnRenameStorage` | Yes | Yes | Yes | Yes |
| Recovery code count and regenerate | `RecoveryCodeStorage` | Yes | Yes | Yes | Yes |
| Durable TOTP replay protection | `TOTPReplayStorage` | Yes | Yes | Pending | Pending |
| Session list, idle timeout, step-up | `SessionManagementStorage` | Yes | Yes | Pending | Pending |
| Session links | `SessionLinkStorage` | Yes | Yes | Pending | Pending |
| Scoped API tokens | `APITokenStorage` | Yes | Yes | Pending | Pending |
| Device grant (RFC 8628) | `DeviceCodeStorage` | Yes | Yes | Pending | Pending |
| Shared login throttle store | `LoginThrottleStore` | In-process default | Yes | In-process default | In-process default |
| Organizations, SAML, SCIM, RBAC | `OrganizationStorage`, `SAMLStorage`, `SCIMStorage`, `RBACStorage` | Yes | No | Yes | Yes |
| OAuth 2.1 authorization server, agent identity | `OAuthServerStorage` | Yes | No | Yes | Yes |
| CIBA backchannel auth | `CIBAStorage` | Yes | No | Yes | No |
| Durable JWT-bearer `jti` replay | `JWTBearerStorage` | Yes | No | No | No |

"Pending" means the capability is not implemented in the Postgres and MySQL adapters on this branch, so enabling the feature with those backends returns `ErrStorageMissingCapability` from `New`. Work to add them is tracked separately; check the changelog before relying on either state.

Notes:

- Without `JWTBearerStorage`, JWT-bearer replay protection uses an in-process map and is lost on restart. Without `CIBAStorage`, `/oauth/bc-authorize` is not mounted.
- Without `TOTPReplayStorage`, the last used TOTP step is tracked in process memory only.
- Without `RecoveryCodeStorage` or `WebAuthnRenameStorage`, the matching routes answer 501 and everything else works.
- The login throttle store is a separate hook, `Config.LoginThrottle.Store`. SQLite provides `Store.ThrottleStore()` so several processes on one database share counters. Others use the in-process default or a store you supply.

## Which feature needs which capability

| You enable | Needs |
|---|---|
| Email and password, magic link, cookies | `CoreStorage` |
| `Config.Bootstrap` | `UserCountStorage` |
| `Config.APITokens`, `RequireAbility`, `MintAPIToken` | `APITokenStorage` |
| `APITokensConfig.Device`, `clientauth.DeviceLogin` | `APITokenStorage` and `DeviceCodeStorage` |
| `RequireRecentAuth`, `POST /auth/step-up`, `GET /auth/sessions`, `SessionIdleTimeout` | `SessionManagementStorage` |
| `Config.SessionLinks` | `SessionLinkStorage` |
| `Config.WebAuthn`, `Config.TOTP` | `WebAuthnStorage`, `TOTPStorage` (and `EncryptionKey` for TOTP) |
| `Config.Organizations`, `SAML`, `SCIM`, `RBAC`, `Admin` | The org, SAML, SCIM and RBAC interfaces |
| `Config.AuthorizationServer`, `AgentIdentity` (OAuth agents) | `OAuthServerStorage` |

Agent tokens minted with `MintAgentToken` are API tokens (`kind=agent`), so they need only `APITokenStorage`, not the OAuth server.

## Choosing a backend

- **memory**: tests and demos. State is lost on restart.
- **sqlite** (`storage/sqlite`, separate module, Go 1.26): single-binary and single-host apps, CLIs with a local server, edge boxes. Covers sign-in, passkeys, TOTP, sessions with step-up, API tokens, device login and audit. It has no organizations, SAML, SCIM, RBAC or OAuth authorization server. One process should own the file.
- **postgres**: multi-instance production with the full enterprise and OAuth server surface. Does not yet have the token, device and session-management capabilities listed as pending above.
- **mysql**: same coverage as Postgres except CIBA, with the same pending items.

Pick by the features you need first, host topology second. If you need both API tokens or device login and organizations or the authorization server, no single built-in backend has both today. You can implement the missing capability on your own adapter; see [Write a Custom Storage Backend](../guides/custom-storage-backend.md) and run the `storagetest` suites (`RunAPITokens`, `RunDeviceCodes`, `RunSessionManagement`) against it.
