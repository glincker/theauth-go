# Stability and security overview

Packages and APIs that were Stable before v2.6 keep their SemVer guarantees. Among the additions in v2.6, only the storage capability split, `Handler()` and `Config.PathPrefix` are Stable. Experimental: `storage/sqlite`, `clientauth`, `policy`, the agent identity and revocation APIs, `Doctor`, `Config.ProviderResolver` and the new optional storage capabilities. Experimental APIs may change in a minor release. The SemVer rules and the list of stable packages are in [STABILITY.md](https://docs.theauth.dev/go/reference/stability).

## Security

- Passwords are hashed with Argon2id, sessions are opaque and stored server side, and agent secrets are shown once and stored only as hashes.
- Release assets are signed with cosign, ship an SBOM and carry SLSA 3 provenance. See [Verify releases](./INSTALL.md#verify-releases).
- CI runs CodeQL, `govulncheck`, dependency review and OpenSSF Scorecard.
- The [threat model](https://docs.theauth.dev/go/security/threat-model) and the `theauth-doctor` [security doctor](https://docs.theauth.dev/go/guides/security-doctor) describe what is covered and how to check a deployment.
- Report vulnerabilities privately through [GitHub advisories](https://github.com/glincker/theauth-go/security/advisories/new) or support@glinr.com, as described in the [security policy](../.github/SECURITY.md). Do not open a public issue.
