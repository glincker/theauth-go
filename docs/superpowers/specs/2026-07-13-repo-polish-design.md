# Repo Polish: Root Tidy-Up + GitHub Metadata/SEO Design

**Goal:** Shrink the visual footprint of the repo's root listing without any
breaking change, and make the GitHub repo page itself (description, topics,
homepage, releases, discussions) actually reflect what theauth-go does, for
discoverability and first-impression trust.

**Architecture:** Two independent, low-risk changes bundled into one PR to
minimize CI runs: (1) relocate community-health docs into `.github/` and
`ROADMAP.md` into `docs/`, both directories GitHub already recognizes for
those files; (2) update repo-level metadata via `gh repo edit` / `gh release
edit` (no CI cost, not part of this PR's diff).

**Tech Stack:** Git file moves, `gh` CLI for repo/release metadata, GraphQL
API for Discussions inspection.

---

## Root tidy-up

**Moved (git mv, path only, GitHub still recognizes these locations for
Community Standards / issue templates):**
- `CODE_OF_CONDUCT.md` → `.github/CODE_OF_CONDUCT.md`
- `CONTRIBUTING.md` → `.github/CONTRIBUTING.md`
- `SECURITY.md` → `.github/SECURITY.md`
- `SUPPORT.md` → `.github/SUPPORT.md`
- `ROADMAP.md` → `docs/ROADMAP.md`

**Deliberately NOT moved:**
- The ~30 root `.go` files (the root Go package, `package theauth`). Moving
  these would change the public import path (`github.com/glincker/theauth-go`
  → something else), a breaking change for every consumer. Out of scope
  regardless of visual root-listing concerns.
- `README.md`, `LICENSE`, `CHANGELOG.md` — strong convention (GitHub requires
  README/LICENSE in root for recognition; CHANGELOG in root is expected by
  tooling and contributor habit).
- `llms.txt` — per the llms.txt spec (llmstxt.org), must live at the root,
  same convention as `robots.txt`.
- Build/lint config (`.golangci.yml`, `.goreleaser.yml`, `sqlc.yaml`,
  `go.work`, `go.work.sum`) — tool defaults expect these in root; relocating
  adds contributor friction for no visual-footprint win worth the churn.

**References updated** (grep-verified, all internal links/comments pointing
at the old paths):
- `README.md`: doc table (added a `ROADMAP.md` row, previously undiscoverable
  from the README at all), "Security" section, "Contributing" section, and
  fixed a pre-existing broken `MIGRATION.md` link (pointed at root, file
  actually lives in `docs/` already, unrelated to this move but caught in the
  same grep sweep).
- `docs-site/docs/security/threat-model.md`: absolute GitHub blob URL to
  `SECURITY.md`.
- `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/security_advisory.yml`:
  absolute GitHub blob URLs to `SECURITY.md`.
- `.github/workflows/ci.yml`, `storage/postgres/postgres_test.go`,
  `storage/mysql/mysql_test.go`: comment references to `ROADMAP.md`.
- `.github/CONTRIBUTING.md`'s own link to `CODE_OF_CONDUCT.md` needed no
  change — both files now live in the same directory, so the relative link
  still resolves.

## GitHub metadata / SEO

Applied directly via `gh repo edit` / `gh release edit` (no code change, no
CI run, not part of this PR's diff):

- **Description** replaced the stale "Session-based auth for Go. Magic links,
  chi middleware, Postgres + in-memory storage." with one naming the actual
  scope (OAuth 2.1 authorization server, WebAuthn/passkeys, TOTP, SAML, SCIM,
  RBAC, MCP resource-server authorization, Postgres/MySQL/in-memory storage).
- **Homepage URL** set to `https://theauth.dev/go/` (was empty).
- **Topics**: kept the existing 15, added `authentication`, `passkeys`,
  `magic-link`, `session-management`, `identity-provider` (20 total, at
  GitHub's topic cap).
- **Release titles**: `v2.4.0` and `v2.5.0-rc.1` had no descriptive title
  (just the tag repeated) unlike `v2.1.0`-`v2.3.0`; gave both a summary title
  matching the existing convention. Also fixed `v2.2.0`'s title, which used an
  em dash (violates this project's "no em dashes" writing rule).

**Not done in this pass (flagged, not blocking):**
- Custom OG/social-share image — needs a designed asset, not something to
  generate blind; a future task if the user wants one.
- Discussions categories — already has 6 sensible default categories
  (Announcements, General, Ideas, Polls, Q&A, Show and tell); no changes
  needed there.
- A discussion titled "[HIRING] Lead Sales Consultant..." (#51) is unrelated
  spam from an unaffiliated account. Flagged to the user rather than deleted
  unilaterally, since deleting existing content the agent didn't create
  wasn't something the original request specifically authorized.

## Testing

- `go build ./...` after the file moves (root package unaffected, moves are
  non-Go files only) — confirmed passing.
- YAML validation on the two edited issue templates — confirmed parses.
- Manual grep sweep for the four old filenames across `*.md`/`*.yml`/`*.go`
  confirmed no remaining broken references (historical spec docs under
  `docs/superpowers/specs/` intentionally left as-is — they're a point-in-time
  record, not live documentation).
