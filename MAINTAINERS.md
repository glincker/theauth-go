# Maintainers

theauth-go is maintained by GLINR STUDIOS, a GLINCKER LLC project. No
individual maintainers are named in this file.

Governance and decision rules are in [GOVERNANCE.md](GOVERNANCE.md).

## Contact

- Security, conduct and general inquiries: support@glinr.com
- Vulnerability reports: GitHub private vulnerability reporting, as described
  in [.github/SECURITY.md](.github/SECURITY.md)
- Questions and ideas:
  [GitHub Discussions](https://github.com/glincker/theauth-go/discussions)
- Bugs and feature requests:
  [GitHub issues](https://github.com/glincker/theauth-go/issues)

[.github/SUPPORT.md](.github/SUPPORT.md) says which channel fits which need.

## Maintainer responsibilities

- Keep CI on `main` passing.
- Review pull requests and triage issues and discussions.
- Apply the contribution, security and conduct policies.
- Keep CHANGELOG.md accurate, including upgrade notes for behavior changes.
- Cut releases by the steps in [docs/RELEASING.md](docs/RELEASING.md).

## Review and merge

- Prefer small, focused pull requests, and keep unrelated refactors out of
  feature and fix changes.
- Behavior changes need tests.
- Commit messages use `<type>: <description>`, as described in
  [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md).
- Breaking changes are handled under [the stability policy](https://docs.theauth.dev/go/reference/stability).

## Releases

Maintainers follow [docs/RELEASING.md](docs/RELEASING.md): changelog PR, signed
annotated tag, release workflow, verification of signatures and attestations,
then sub-module tags. No release cadence is promised.

### Release discussion

When the `release` workflow succeeds, the `release-discussion` workflow adds the
release to the shared monthly `Releases YYYY-MM` thread in
`glincker/theauth` Discussions (Announcements) and links the thread from the
GitHub release notes. `theauth` (the TypeScript SDK) writes to the same thread,
each repo owning its own section. It needs the `DISCUSSIONS_TOKEN` secret
(Discussions write on `glincker/theauth`, GitHub App or fine-grained PAT). To
backfill or retry, run the workflow from the Actions tab with the tag.

## Incidents

- Security issues follow [.github/SECURITY.md](.github/SECURITY.md).
- For a bad release, the rollback steps are in
  [docs/RELEASING.md](docs/RELEASING.md). A published version number is never
  reused; fix forward with a new patch version.
