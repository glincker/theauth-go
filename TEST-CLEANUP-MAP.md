# Test Cleanup Map

This document tracks every decision made during the root test file cleanup
(PR refactor/root-test-cleanup-2026-06-22). One row per file. Files are
categorized A-F per the original spec.

## Legend

| Code | Meaning |
|------|---------|
| A    | KEEP in root (legitimately tests public root API) |
| B    | MOVE to internal package (black-box test of internal feature via root facade) |
| C    | MOVE to e2e_test/ with //go:build e2e tag |
| D    | MOVE to internal/theauthtest/ (shared fixture helpers) |
| E    | MOVE to internal/fuzz/ (fuzz tests) |
| F    | CONSOLIDATE (multiple small files merged) |

## Before / After

- Root test files BEFORE this PR: 35
- Root test files AFTER this PR: 27
- Net reduction: 8 files removed from root
- New internal test files added: 9 (internal/audit x4, internal/saml x1, internal/organizations x1, internal/scim x2, internal/theauthtest x1)

## Constraint: ForTest bridge functions

The `export_test.go` file (package theauth) exposes unexported symbols via
bridge functions (IssueSessionForTest, ValidateSessionForTest, etc.). These
bridges are compiled into the test binary only for tests in the root
module's test compilation unit. Tests in `package session_test`,
`package password_test`, etc. (separate compilation units) cannot call them.

This constraint prevents moving session, password, magiclink, totp, and
account-linking tests to their internal packages without first either:
(a) promoting the bridge functions to the main package API, or
(b) creating a separate testable shim package.

Files blocked by this constraint are marked A with a note and held for a
follow-up PR.

## File Decisions

| Filename | Decision | Destination | Reasoning |
|----------|----------|-------------|-----------|
| audit_test.go | B | internal/audit/audit_test.go | Tests public audit API (DefaultRedactor, EmitAudit, Stats) but does not need root-package ForTest bridges. Audit is a self-contained subsystem. |
| audit_redactor_depth_test.go | B | internal/audit/audit_redactor_depth_test.go | Same rationale as audit_test.go. Tests DefaultRedactor deep-nesting and high-concurrency emission. |
| audit_perf_test.go | B | internal/audit/audit_perf_test.go | Tests case-insensitive key matching. Same rationale. |
| audit_sinks_test.go | B | internal/audit/audit_sinks_test.go | Tests AuditSink interface contracts (fail sink, redactor override). Same rationale. |
| handlers_scim_test.go | B | internal/scim/handlers_scim_test.go | Tests SCIM HTTP endpoints via public API only. The newUser helper is replaced by theauthtest.NewUser. The newSCIMTestStack helper is needed by scim_patch_test.go so they move together. |
| scim_patch_test.go | B | internal/scim/scim_patch_test.go | Tests SCIM PATCH branch matrix via HTTP endpoints. Depends on newSCIMTestStack (moved with handlers_scim_test.go). Only imports public theauth types. |
| service_organizations_test.go | B | internal/organizations/service_organizations_test.go | Tests public Organizations API (CreateOrganization, AddOrganizationMember, etc.). The newUser helper is replaced by theauthtest.NewUser. No ForTest bridges needed. |
| service_saml_test.go | B | internal/saml/service_saml_test.go | Tests public SAML API (FinishSAMLLogin, CreateSAMLConnection, etc.). The newUser helper is replaced by theauthtest.NewUser. No ForTest bridges needed. |
| export_test.go | A | (root) | Package theauth (white-box). Exposes unexported functions for external tests. Must stay in root. |
| models_test.go | A | (root) | Package theauth (white-box). Tests internal JSON serialization contracts and Session.Expired logic. Must stay in root. |
| errors_test.go | A | (root) | Tests public error types and error wrapping. Legitimately root. |
| theauth_example_test.go | A | (root) | Example functions for godoc (ExampleNew). Must stay in root. |
| handlers_example_test.go | A | (root) | Example functions for godoc (ExampleTheAuth_Mount). Must stay in root. |
| middleware_example_test.go | A | (root) | Example functions for godoc (ExampleTheAuth_Authn). Must stay in root. |
| handlers_test.go | A | (root) | Core HTTP end-to-end flow tests. Defines newTestServer/postJSON/getAuth helpers. Also uses ForTest bridges (SetBaseURLForTest, RequestPasswordResetForTest). |
| handlers_admin_test.go | A | (root) | Tests admin HTTP endpoints through the root Mount facade. |
| handlers_admin_agents_test.go | A | (root) | Tests admin agent HTTP endpoints. Uses newASInstance-style fixture. |
| handlers_oauth_test.go | A | (root) | Tests OAuth provider callback handlers via HTTP. |
| handlers_oauth_multi_test.go | A | (root) | Tests multi-provider OAuth registration. |
| handlers_totp_test.go | A | (root) | Tests TOTP HTTP endpoints. Uses newTestServer from handlers_test.go. |
| handlers_fuzz_test.go | A | (root) | Fuzz targets for session cookie and handler paths. Defines newFuzzAuth. |
| handlers_oauth_fuzz_test.go | A | (root) | Fuzz target for OAuth callback query parameters. Uses newOAuthFuzzAuth. |
| fuzz_helpers_test.go | A | (root) | Shared fuzz fixture helpers (stubProvider, newOAuthFuzzAuth). Used by handlers_fuzz and handlers_oauth_fuzz. |
| middleware_ratelimit_test.go | A | (root) | Tests rate-limit middleware via HTTP and service layer. Uses newTestAuth from service_session_test.go. |
| middleware_ratelimit_race_test.go | A | (root) | Race condition test for keyedLimiter. Uses NewKeyedLimiterForTest (ForTest bridge). |
| middleware_ratelimit_perf_test.go | A | (root) | Benchmark for rate limiter hot path. Uses NewKeyedLimiterForTest. |
| service_session_test.go | A (held) | (root) | Uses IssueSessionForTest + ValidateSessionForTest (ForTest bridges). Cannot move to internal/session_test without rearchitecting the bridge pattern. Follow-up PR should promote session service to a testable internal API. |
| service_session_race_test.go | A (held) | (root) | Same ForTest bridge constraint as service_session_test.go. |
| service_magiclink_test.go | A (held) | (root) | Uses RequestMagicLinkForTest + ConsumeMagicLinkForTest. Same constraint. |
| service_password_test.go | A (held) | (root) | Uses SignupWithPasswordForTest, SigninWithPasswordForTest, etc. Same constraint. |
| service_password_fuzz_test.go | A (held) | (root) | Uses ValidateEmailForTest (ForTest bridge). Could move to internal/fuzz but the bridge constraint still applies. |
| service_totp_test.go | A (held) | (root) | Uses BeginTOTPEnrollmentForTest, VerifyTOTPForTest, etc. Same constraint. |
| service_account_linking_test.go | A (held) | (root) | Uses IssueSessionForTest, LinkOAuthForTest, MergeAccountsForTest. Same constraint. |
| service_oauth_race_test.go | A (held) | (root) | Tests OAuth state concurrency. Could move to internal/oauth but file is small and self-contained. Low priority. |
| observability_test.go | A | (root) | Intentionally stays in root to test that public re-exported types (theauth.Tracer, theauth.Span, theauth.Attr) are usable by downstream consumers building their own adapters. The file comment explains this explicitly. |

## New Package: internal/theauthtest

Created at `internal/theauthtest/theauthtest.go`. Exports:

- `NewTestAuth(t) (*TheAuth, *memory.Store)` - standard in-memory auth instance
- `NewUser(t, store, email) User` - inserts a user row and returns it

Used by: internal/saml, internal/organizations, internal/scim.

## Follow-up Opportunities (not in this PR)

1. **ForTest bridge refactor**: Consider moving internal service functions to
   testable internal packages with exported test constructors, eliminating
   the need for export_test.go bridges. This would unlock moving ~8 more
   root test files.

2. **service_oauth_race_test.go consolidation**: Small file (90 lines)
   that could move to internal/oauth once the OAuth service is extracted
   into its own testable package.

3. **Fuzz consolidation**: handlers_fuzz_test.go, handlers_oauth_fuzz_test.go,
   fuzz_helpers_test.go, and service_password_fuzz_test.go could be
   consolidated under internal/fuzz/ once the ForTest bridge constraint is
   resolved.
