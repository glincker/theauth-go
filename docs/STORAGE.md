# Storage backends

Persistence is split into small capability interfaces, and `New` fails at startup if a feature you enabled has no matching capability. Full matrix: [Capability interfaces](https://docs.theauth.dev/go/concepts/capability-interfaces).

| Capability | memory | sqlite | postgres | mysql |
|---|---|---|---|---|
| Users, sessions, magic links, passwords | Yes | Yes | Yes | Yes |
| OAuth accounts, passkeys, TOTP, audit log | Yes | Yes | Yes | Yes |
| Scoped API tokens, device grant, session management | Yes | Yes | Yes | Yes |
| Organizations, SAML, SCIM, RBAC | Yes | Yes | Yes | Yes |
| OAuth 2.1 authorization server, agent identity | Yes | Yes | Yes | Yes |
| CIBA backchannel auth | Yes | Yes | Yes | No |
| OAuth device grant (RFC 8628) and registration tokens | Yes | Yes | Yes | Yes |
| Durable JWT-bearer `jti` replay | Yes | Yes | No | No |

Postgres and MySQL implement the newer token, device, session and throttle capabilities and pass the new `storagetest` suites against live PostgreSQL 16 and MySQL 8. The full shared contract passes on Postgres when you opt in with `THEAUTH_PG_CONTRACT=1` and a DSN in `THEAUTH_TEST_PG_DSN` (verified on PostgreSQL 14), but that gate is not enabled in CI yet. The MySQL gate is still off, so treat MySQL support for the newer features as newly added. You can write your own backend and verify it with the public [`storagetest`](../storagetest) suite.
