# Security policy

## Supported versions

| Version | Supported |
|---|---|
| v2.x (current minor) | Yes -- active security fixes |
| v2.x (previous minor) | Yes -- security fixes only |
| v1.x | No |
| v0.x | No |

We support the current minor release and the previous minor release with security backports. Upgrade to the latest patch of the current minor to receive all fixes.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

**Option 1 (preferred): GitHub Security Advisories**

Use [GitHub's private vulnerability reporting](https://github.com/glincker/theauth-go/security/advisories/new). This keeps the report confidential until a fix is published.

**Option 2: Email**

Send a report to **security@glincker.com**. Include:

- A description of the issue and potential impact
- Steps to reproduce or a proof-of-concept
- The version(s) affected
- Any suggested mitigation you have already identified

## Response SLA

| Severity | Acknowledgement | Triage + fix target |
|---|---|---|
| Critical / High | 48 hours | 14 days |
| Moderate | 48 hours | 30 days |
| Low / Informational | 5 business days | Next scheduled release |

## Disclosure policy

We follow responsible disclosure. Once a fix is available we will:

1. Publish a patched release.
2. Add a security advisory on the GitHub repository.
3. Credit the reporter in the advisory (unless you prefer to remain anonymous).

We will coordinate a disclosure timeline with you before publishing.

## Scope

In scope:

- Authentication or authorization bypasses in the library itself
- Token leakage or session fixation
- Timing side-channels in credential comparison (we use `crypto/subtle`)
- SQL injection or unsafe query construction in the storage adapters
- Cryptographic weaknesses in token, PKCE, or JWT handling
- Issues in the `mcpresource` JWT validation or actor-chain walking
- DPoP binding bypass or nonce replay vulnerabilities
- CIBA backchannel authorization bypass

Out of scope:

- Vulnerabilities in Go's standard library or third-party dependencies (report those upstream)
- Issues requiring physical access to the server
- Social engineering
- Vulnerabilities in example apps that do not reflect patterns in the library itself

## Recent security fixes

### 2026-06-20 audit

- **H1**: DCR bearer gate now uses constant-time comparison against pre-hashed tokens
- **H2**: POST `/oauth/register` is now rate-limited per source IP
- **H3**: Cross-org delegation admin now verifies org membership before creating grants
- **H4**: `X-Forwarded-For` is no longer trusted by default; requires `Config.TrustedProxies`
- **M2**: `AddOrganizationMember` now refuses to demote the last owner
- **M6**: Password signin pays Argon2id cost on unknown-email branch to close timing side-channel
