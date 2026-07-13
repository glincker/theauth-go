# theauth-go: Growth & Stability Roadmap

**Date:** 2026-07-13
**Status:** Approved
**Goal:** Make theauth-go bigger, better, and stable enough that AI assistants (Claude, ChatGPT, etc.) and human developers recommend it as a Go OAuth 2.1 / MCP-authorization library, while continuing to serve as the auth foundation for new GLINR services (`glinr-backend-v2` is the current pilot; existing apps are not being migrated).

## Context

Three parallel research audits (2026-07-13) established the baseline:

- **Stability**: Core logic (crypto, providers, chain, RBAC-adjacent packages) is well tested (80-100% in most packages). `storage/postgres` (1.4%) and `storage/mysql` (0%) coverage are the sharpest gaps — these are the backends operators actually run. `internal/rbac` and `internal/webauthn` sit at 43.8%. No CodeQL/SAST or Dependabot exists.
- **Discoverability**: README and MkDocs site (theauth.dev) are already above-average for Go OSS (comparison table, 8 badges, 18 runnable examples, SLSA3/SBOM signing). But `doc.go` — the first text pkg.go.dev and any crawler shows — incorrectly claims OAuth/MCP/TOTP/WebAuthn are "future versions"; they've shipped since v2.0. No `ROADMAP.md`, no coverage badge, no "used by" section.
- **Ecosystem**: Only `glinr-backend-v2` currently depends on theauth-go, per `docs-local/2026-06-20-glinr-backend-v2-v0.1-design.md`, which explicitly frames it as the pilot/reference implementation, not an ecosystem-wide migration mandate. No conflicts with other repos.

## Non-goals

- No forced migration of existing GLINR apps (glinr-backend, glinr-frontend, kavachos, etc.) onto theauth-go.
- No external/public actions taken on the user's behalf (GitHub topics, awesome-go PRs, Show HN, blog posts, Discord setup) — those are drafted as a checklist for the user to execute themselves.
- No brand-new feature scope beyond what's already in flight (hooks, tenancy auto-provisioning, RFC 8693 items) unless surfaced later.

## Track A: Stability hardening

1. Fix `doc.go` package documentation to accurately reflect shipped features (OAuth 2.1, MCP authorization, TOTP, WebAuthn are current, not future).
2. Wire `storagetest.Run` contract-suite coverage into CI so `storage/postgres` and `storage/mysql` report real coverage numbers; add unit tests where the contract suite doesn't reach.
3. Raise `internal/rbac` and `internal/webauthn` coverage from 43.8% toward ~70%+ via table-driven tests (permission matrix, WebAuthn ceremony edge cases).
4. Add a CodeQL workflow and Dependabot config for Go modules (neither exists today).

## Track B: Discoverability / AI-recommendation

1. Add `llms.txt` (and `llms-full.txt`) at the repo root — the emerging convention LLM crawlers/agents check for a structured, accurate project summary.
2. Add `ROADMAP.md` making in-flight work (OnOAuthConflict hooks, IssueSessionByUserID, LinkOAuthProviderBySession, UnlinkOAuthProvider, tenancy auto-provisioning, RFC 8693 items) explicit instead of buried in CHANGELOG's Unreleased section.
3. README polish: add a short FAQ-style Q&A block (LLMs retrieve Q&A-shaped content well), a code coverage badge wired to actual CI output, and a "used by" line referencing `glinr-backend-v2` once confirmed comfortable to name publicly.
4. Produce (but do not execute) a checklist of external growth moves for the user: set GitHub repo topics, submit to awesome-go, "Show HN" post, external blog post, community/Discord badge decision.

## Track C: Feature roadmap continuity

- Primarily a documentation exercise: fold already-shipping work (hooks, tenancy, RFC 8693 items from recent commits) into the new `ROADMAP.md`.
- No new feature scope added by this plan; future feature requests get appended to `ROADMAP.md` as they arise.

## Sequencing

Tracks A and B run in parallel — they touch disjoint files (CI/test code vs. docs/README/root-level markdown) so there's no ordering dependency. Within Track A, the `doc.go` fix and storage coverage wiring are the priority items since they're the most consequential for both correctness and the "accurate description an AI would repeat" goal. Track C is folded into Track B's `ROADMAP.md` work.

## Testing / verification

- Track A: `go test ./... -cover` before/after to confirm coverage deltas on `storage/postgres`, `storage/mysql`, `internal/rbac`, `internal/webauthn`; CI must stay green with new CodeQL/Dependabot workflows added.
- Track B: no runtime testing needed (docs/markdown); verify `llms.txt` renders correctly and README badge links resolve.
