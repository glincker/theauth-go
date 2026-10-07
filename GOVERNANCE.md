# Governance

This document describes who maintains theauth-go and how decisions are made.

theauth-go is maintained by GLINR STUDIOS, a GLINCKER LLC project. It is
released under the license in [LICENSE](LICENSE). The maintainer team is
described by role in [MAINTAINERS.md](MAINTAINERS.md); no individuals are named
there.

## Goals

- Provide auth building blocks for Go services: sessions, OAuth 2.1 and MCP
  authorization, passkeys, SAML, SCIM and agent identity.
- Keep the public API stable under Semantic Versioning.
- Be plain about what is and is not covered. Known gaps are listed in
  [docs/ROADMAP.md](docs/ROADMAP.md), and the
  [threat model](https://docs.theauth.dev/go/security/threat-model) and
  compliance pages say what they do not claim.

## Roles

### Maintainers

Maintainers review and merge pull requests, triage issues and discussions, tag
releases, and handle private security reports. They act for GLINR STUDIOS.

### Contributors

Anyone can open an issue or discussion, send a pull request, or improve docs,
tests and examples. How to do that is in
[.github/CONTRIBUTING.md](.github/CONTRIBUTING.md).

## How decisions are made

Routine changes (bug fixes, docs, tests, non-breaking additions) are decided in
pull request review by a maintainer.

Larger changes need more up front:

1. Open an issue or a
   [GitHub Discussion](https://github.com/glincker/theauth-go/discussions)
   describing the change before writing code.
2. State the compatibility impact. What counts as a breaking change, and how
   deprecations work, is in [the stability policy](https://docs.theauth.dev/go/reference/stability).
3. A maintainer agrees to the direction, then the pull request is reviewed like
   any other. New behavior needs tests.

Planned work is tracked in [docs/ROADMAP.md](docs/ROADMAP.md). It lists no
dates and commits to nothing beyond what it says.

## Releases

How a release is cut is written down in [docs/RELEASING.md](docs/RELEASING.md):
a dated CHANGELOG section with upgrade notes first, a signed annotated tag, the
release workflow (tests, SBOM, cosign signatures, provenance attestation), and
sub-module tags afterward. This project does not publish a release schedule.
Behavior changes and upgrade notes are in [CHANGELOG.md](CHANGELOG.md).

## Security and conduct

- Report vulnerabilities privately as described in
  [.github/SECURITY.md](.github/SECURITY.md). Do not open public issues for
  them.
- Community behavior follows
  [.github/CODE_OF_CONDUCT.md](.github/CODE_OF_CONDUCT.md).
- Anything that does not fit a public channel: support@glinr.com.

## Becoming a maintainer

No formal process is defined yet. If you have contributed steadily and want to
help maintain the project, say so in a discussion or write to
support@glinr.com.

## Changing this document

Changes to GOVERNANCE.md and MAINTAINERS.md go through a pull request like any
other change.
