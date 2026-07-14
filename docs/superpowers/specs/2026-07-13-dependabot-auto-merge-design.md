# Dependabot Auto-Merge Design

**Goal:** Stop Dependabot PRs from piling up unreviewed while keeping a human in the
loop for anything that touches theauth-go's security boundary.

**Architecture:** A `pull_request`-triggered workflow classifies each Dependabot PR
using `dependabot/fetch-metadata`, then either enables GitHub's native auto-merge
(so it merges itself once CI passes) or labels it `needs-review` and comments why.
Modeled on `GLINCKER/thesvg`'s `dependabot-auto-merge.yml`, adapted for Go's
dependency shape and this repo's security-sensitive surface.

**Tech Stack:** GitHub Actions, `dependabot/fetch-metadata@v3`, `gh` CLI.

---

## Classification policy

1. **Patch bump, any dependency** → auto-merge. CI (build/vet/test/lint/CodeQL) is
   the safety net for behavior regressions; patch releases are supposed to be
   backwards-compatible bugfixes.
2. **Minor or major bump, non-security dependency** → auto-merge. Matches thesvg's
   policy: dev-only deps, GitHub Actions, and general runtime deps.
3. **Minor or major bump, security-relevant dependency** → hold. Labeled
   `needs-review` with a PR comment explaining why. A maintainer should read
   release notes before shipping a version bump on anything touching the auth
   library's crypto/identity-verification surface, regardless of semver band.
4. **GitHub Actions bump, any version** → auto-merge. These are build/CI tooling,
   not part of the library's runtime security surface.

**Security-relevant dependency list** (module path prefixes, matched against
`dependabot/fetch-metadata`'s `dependency-names` output):

- `golang.org/x/crypto`
- `github.com/golang-jwt/jwt`
- `github.com/crewjam/saml`
- `github.com/russellhaering/goxmldsig`
- `github.com/go-webauthn/`
- `github.com/pquerna/otp`
- `github.com/beevik/etree`
- `filippo.io/edwards25519`
- `github.com/fxamacker/cbor`
- `github.com/mattermost/xml-roundtrip-validator`
- `github.com/google/go-tpm`

This list is a plain bash substring match in the workflow step, not a separate
config file — it changes rarely enough that editing the workflow directly is
simpler than maintaining a second source of truth.

## Workflow file

`.github/workflows/dependabot-auto-merge.yml`, triggered on
`pull_request: [opened, reopened, synchronize, ready_for_review]`, gated to
`github.event.pull_request.user.login == 'dependabot[bot]'`.

Steps:
1. `dependabot/fetch-metadata@v3` → gives `update-type`, `dependency-names`,
   `package-ecosystem`, `dependency-type`.
2. Compute `is-security-relevant` by grepping `dependency-names` against the list
   above.
3. If `package-ecosystem == 'github_actions'` OR `update-type == patch` OR
   (`update-type` is minor/major AND NOT security-relevant) → 
   `gh pr merge --auto --squash --delete-branch`.
4. Else (minor/major AND security-relevant) → create/apply `needs-review` label
   (reuse existing label, already present in this repo) and comment explaining
   the hold.

## Existing backlog (19 open PRs)

The workflow only fires on new PR events, so it does not retroactively touch
already-open PRs. Per the chosen approach, the same classification is applied
once by hand via `gh pr merge --auto` / `gh pr edit --add-label` on the current
19, rather than triggering `@dependabot recreate`:

**Auto-merge (16):** #92, #93, #94, #95, #96, #98, #100, #101, #103 (GitHub
Actions bumps) + #97, #99, #102, #104 (protobuf/otel-proto, non-security) + #105,
#107, #109 (echo/otel/gin bumps scoped to example-only modules, non-security).

**Hold for review (3):** #106 (`beevik/etree`), #108 (`pquerna/otp`), #110
(`russellhaering/goxmldsig`) — each labeled `needs-review` with an explanatory
comment.

## Testing

No unit tests apply (this is a CI workflow + one-time PR triage). Verification is:
- `yamllint`-equivalent check (the workflow YAML parses and its `if:` expressions
  are syntactically valid) before committing.
- After merge, confirm the 16 auto-merge PRs actually complete (native GitHub
  auto-merge may take a few minutes per PR to churn through CI) and the 3 held
  PRs carry the `needs-review` label and comment.

## Data gaps / follow-ups (not in scope here)

- GitHub Actions in this repo are pinned by major-version tag (e.g. `@v4`), not by
  commit SHA. Pinning-by-SHA is a stronger supply-chain practice but is a
  separate, larger change (touches every workflow file) — out of scope for this
  workstream, worth a future ROADMAP.md entry.
- `examples/*` directories are not tracked in `dependabot.yml` (a deliberate scope
  decision from the earlier growth-stability roadmap work), so #105/#107/#109 are
  the last dependency bumps those modules will ever get automatically. Not
  addressed here — flagging in case it's worth revisiting later.
