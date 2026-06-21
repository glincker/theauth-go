# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| v2.0.x (current) | Yes |
| v1.0.x | Security fixes only |
| v0.x | No |

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Send a report to **security@glincker.com**. Include:

- A description of the issue and the potential impact
- Steps to reproduce or a proof-of-concept
- The version(s) affected
- Any suggested mitigation you have already identified

You will receive an acknowledgement within 48 hours. We aim to triage and produce a fix within 14 days for critical issues and 30 days for moderate ones. We will coordinate a disclosure timeline with you before publishing.

## Disclosure policy

We follow responsible disclosure. Once a fix is available we will:

1. Publish a patched release.
2. Add a security advisory on the GitHub repository.
3. Credit the reporter in the advisory (unless you prefer to remain anonymous).

## Scope

In scope:

- Authentication or authorization bypasses in the library itself
- Token leakage or session fixation
- Timing side-channels in credential comparison (we use `crypto/subtle`)
- SQL injection or unsafe query construction in the storage adapters
- Cryptographic weaknesses in token, PKCE, or JWT handling
- Issues in the `mcpresource` JWT validation or actor-chain walking

Out of scope:

- Vulnerabilities in Go's standard library or third-party dependencies (report those upstream)
- Issues requiring physical access to the server
- Social engineering

## Recent security fixes

### 2026-06-20 audit

- **H1**: DCR bearer gate now uses constant-time comparison against pre-hashed tokens
- **H2**: POST `/oauth/register` is now rate-limited per source IP
- **H3**: Cross-org delegation admin now verifies org membership before creating grants
- **H4**: `X-Forwarded-For` is no longer trusted by default; requires `Config.TrustedProxies`
- **M2**: `AddOrganizationMember` now refuses to demote the last owner
- **M6**: Password signin pays Argon2id cost on unknown-email branch to close timing side-channel
