# Releasing theauth-go

This document describes the release process for maintainers.

## Module path and sub-module tagging

The root module path is `github.com/glincker/theauth-go/v2` (one `go.mod` at the
repository root, no `v2` directory). Go requires the `/v2` suffix for major
version 2 and above, so tags `v2.0.0` to `v2.5.0` were never resolvable. The
first resolvable tag is `v2.6.0`.

The sub-modules `storage/sqlite`, `mcpresource`, `audit/sinks/otlp` keep
unversioned paths (major version 0 or 1 needs no suffix) and are tagged with a
directory prefix. Examples are never tagged. In the repository they require the
root through a placeholder version plus `go.work`, so local development works
without any tag.

Tag in this order, from an up to date checkout of the default branch:

```bash
git fetch origin
git tag -l 'mcpresource/*' 'storage/*' 'audit/*'   # check the next number first

# 1. root module (signed, annotated)
git tag -s v2.6.0 -m "v2.6.0"
git push origin v2.6.0

# 2. wait for proxy.golang.org to serve it
GOWORK=off GOPROXY=https://proxy.golang.org go list -m github.com/glincker/theauth-go/v2@v2.6.0

# 3. per sub-module: replace the placeholder require, tidy, commit
for d in storage/sqlite audit/sinks/otlp; do
  (cd "$d" && GOWORK=off go mod edit -dropreplace=github.com/glincker/theauth-go/v2 \
     -require=github.com/glincker/theauth-go/v2@v2.6.0 && GOWORK=off go mod tidy)
done
git commit -am "chore: pin sub-modules to theauth-go v2.6.0"
# merge that commit through a PR, then tag the merged commit:

# 4. sub-module tags (mcpresource has no root dependency, tag it any time)
git tag -s storage/sqlite/v0.1.0 -m "storage/sqlite v0.1.0"
git tag -s audit/sinks/otlp/v0.1.0 -m "audit/sinks/otlp v0.1.0"
git tag -s mcpresource/v0.1.0 -m "mcpresource v0.1.0"
git push origin storage/sqlite/v0.1.0 audit/sinks/otlp/v0.1.0 mcpresource/v0.1.0
```

Use the next free version for each prefix if earlier tags exist. After
`mcpresource` is tagged, bump the root `go.mod` require of it from the
pseudo-version to the tag in the next root release.

Some sub-modules have no `replace` directive today (`storage/sqlite`); after
step 3 they build with `GOWORK=off` from the proxy. Keep `go.work` for local
development, and keep the placeholder require in examples (they use `replace`).

### How consumers install

```bash
go get github.com/glincker/theauth-go/v2
go get github.com/glincker/theauth-go/storage/sqlite   # optional
go get github.com/glincker/theauth-go/mcpresource      # optional
```

Warning: anyone on the old path (including pseudo-versions of
`github.com/glincker/theauth-go`) must change their imports to the `/v2` path.
The old path stays frozen at v1.0.0. See `docs-site/docs/migrations/to-v2-module-path.md`.

## Release checklist

Order matters because sub-modules can only pin the root after the proxy serves it.

- [ ] CHANGELOG.md has a dated `## [X.Y.Z]` section with `### Upgrade notes` first, and compare links at the bottom.
- [ ] `docs/release-notes-vX.Y.Z.md` matches the changelog.
- [ ] `GOWORK=off go build ./... && go test ./...` pass on the default branch.
- [ ] Tag the root module (`vX.Y.Z`) and push it; wait for the release workflow.
- [ ] `go list -m github.com/glincker/theauth-go/v2@vX.Y.Z` resolves through proxy.golang.org.
- [ ] Pin sub-modules to the root tag, merge that PR, then tag sub-modules on the merged commit.
- [ ] Verify cosign and SLSA attestations (steps 5 and 6 below).
- [ ] Publish the release notes and announce.

## Prerequisites

- Write access to `glincker/theauth-go` on GitHub
- `git` configured with GPG or SSH signing (annotated tags are signed by convention)
- `gh` CLI authenticated

## Step-by-step

### 1. Update CHANGELOG.md

Move all entries from the `## [Unreleased]` section into a new versioned
section following Keep-a-Changelog format:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- ...

### Fixed
- ...
```

Leave the `## [Unreleased]` heading in place (empty) for the next cycle.

### 2. Open a PR for the changelog update

```bash
git checkout -b chore/release-vX.Y.Z
git add CHANGELOG.md
git commit -m "chore(release): prepare vX.Y.Z"
git push origin chore/release-vX.Y.Z
gh pr create --title "chore(release): prepare vX.Y.Z" --body "Moves Unreleased entries to vX.Y.Z section."
```

Merge the PR to main after review.

### 3. Tag the release

After the PR is merged, pull main and create an annotated tag:

```bash
git checkout main && git pull origin main
git tag -a vX.Y.Z -m "theauth-go vX.Y.Z"
git push origin vX.Y.Z
```

This tag push triggers `.github/workflows/release.yml` automatically.

### 4. What the workflow does

The release workflow runs goreleaser, which:

1. Runs `go mod tidy` and `go test ./...` as a gate. The release fails if
   either step fails.
2. Creates a source archive `theauth-go-vX.Y.Z.tar.gz`.
3. Generates a CycloneDX SBOM via `syft`: `theauth-go-vX.Y.Z.tar.gz.sbom.json`.
4. Signs all artifacts with `cosign` keyless signing (Sigstore OIDC via
   GitHub Actions identity). Produces `.sig` and `.cert` files for each
   artifact.
5. Creates a GitHub Release with all artifacts attached.
6. Generates a SLSA provenance attestation via
   `actions/attest-build-provenance` for the source archive and SBOM.

### 5. Verify the release (smoke-test)

```bash
# Download assets from the release
gh release download vX.Y.Z --repo glincker/theauth-go --dir /tmp/release-check

# Verify the SBOM signature
cosign verify-blob \
  --certificate-identity "https://github.com/glincker/theauth-go/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature /tmp/release-check/theauth-go-vX.Y.Z.tar.gz.sbom.json.sig \
  --certificate /tmp/release-check/theauth-go-vX.Y.Z.tar.gz.sbom.json.cert \
  /tmp/release-check/theauth-go-vX.Y.Z.tar.gz.sbom.json

# Verify the source archive signature
cosign verify-blob \
  --certificate-identity "https://github.com/glincker/theauth-go/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature /tmp/release-check/theauth-go-vX.Y.Z.tar.gz.sig \
  --certificate /tmp/release-check/theauth-go-vX.Y.Z.tar.gz.cert \
  /tmp/release-check/theauth-go-vX.Y.Z.tar.gz
```

Both commands should print `Verified OK`.

### 6. Verify SLSA provenance

The SLSA attestation is stored in the GitHub Actions artifacts store and
linked from the release via the `actions/attest-build-provenance` step. Use
`gh attestation verify` to check it:

```bash
gh attestation verify /tmp/release-check/theauth-go-vX.Y.Z.tar.gz \
  --repo glincker/theauth-go
```

### 7. Post-release

- Announce in GitHub Discussions if the release has significant changes.
- Update MIGRATION.md if there are any breaking changes.
- If a Slack webhook is configured (`SLACK_WEBHOOK_URL` repository secret),
  the workflow posts a notification automatically.

## Pre-release tags

Tags with `-alpha`, `-beta`, or `-rc` suffixes (e.g. `v2.4.0-rc.1`) are
published as pre-releases automatically (`prerelease: auto` in
`.goreleaser.yml`). Follow the same tag procedure; GitHub marks the release
as a pre-release.

## Rollback

If a bad release is published:

1. Delete the tag: `git push origin :refs/tags/vX.Y.Z`
2. Delete the GitHub Release via `gh release delete vX.Y.Z --repo glincker/theauth-go`
3. Fix the issue, cut a patch release (vX.Y.Z+1), and re-tag.

Do not re-use a version number after publishing it. Consumers may have
cached the module at that version in their module proxy.
