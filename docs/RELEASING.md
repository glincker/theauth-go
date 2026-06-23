# Releasing theauth-go

This document describes the release process for maintainers.

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
