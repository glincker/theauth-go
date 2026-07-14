# Growth & Stability Roadmap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the storage-backend correctness bugs and CI gaps blocking theauth-go's stability story, then ship the discoverability changes (accurate `doc.go`, `llms.txt`, `ROADMAP.md`, README polish) that make it the kind of Go auth library both humans and AI assistants recommend.

**Architecture:** No new subsystems. Every task is a targeted fix or addition to existing files: storage backend bug fixes validated by new regression subtests inside the existing contract tests, CI workflow additions, and root-level documentation/metadata files.

**Tech Stack:** Go 1.25, pgx v5 (Postgres), database/sql + go-sql-driver/mysql (MySQL), GitHub Actions, MkDocs Material (docs-site).

---

## Context for the engineer

Three research passes (2026-07-13) established:

1. `doc.go` (root package doc comment, the first thing pkg.go.dev shows) says OAuth/MCP/TOTP/WebAuthn "land in future versions" — they shipped in v2.0. This is a factual bug.
2. `storage/postgres` and `storage/mysql` have a real, confirmed cross-backend correctness bug: several `UPDATE`-based methods silently return `nil` when the target row doesn't exist, instead of `storage.ErrNotFound`. The **memory backend** (the reference implementation `storagetest.Run` is authoritative against in CI) already returns `storage.ErrNotFound` for every one of these methods — confirmed by reading `storage/memory/*.go` directly. So this isn't a style nit, it's a genuine divergence from the documented storage contract.
3. Because of exactly this class of bug, `TestPostgresStoreContract` in `storage/postgres/postgres_test.go` is gated behind `THEAUTH_PG_CONTRACT=1` and skipped in CI, and the MySQL contract test (`TestMySQLStoreContract` in `storage/mysql/mysql_test.go`) has no CI wiring at all — no MySQL service container exists in `.github/workflows/ci.yml`. This is why `storage/postgres` shows 1.4% coverage and `storage/mysql` shows 0% in `go test -cover` output despite both having real contract tests already written.
4. No CodeQL or Dependabot exists yet.
5. `internal/rbac` (43.8% coverage) has zero test coverage of `DeleteRole` at all, and no not-found-path tests for `UpdateRole`/`RevokeRole`.
6. `internal/webauthn` (43.8% coverage) has zero test coverage of `Service.DeleteCredential` / `Service.ListCredentials` — they're only reachable today via `internal/webauthn/handlers`, never unit-tested directly.
7. `docs/AGENTS.md` already exists and is an excellent, accurate, up-to-date LLM-facing summary of the library — but it lives in `docs/`, not at the repo root or docs-site root, so it's invisible to crawlers checking the emerging `/llms.txt` convention.
8. `docs-site/docs/CNAME` confirms the MkDocs site is deployed to `theauth.dev`; any file dropped in `docs-site/docs/` gets served verbatim (that's how `CNAME` itself works).

---

### Task 1: Fix the stale `doc.go` package documentation

**Files:**
- Modify: `doc.go`

- [ ] **Step 1: Rewrite the package doc comment**

Current content (incorrect — claims shipped features are future work):

```go
// Package theauth provides session-based authentication for Go applications.
//
// TheAuth ships magic-link email auth, opaque session tokens with revocation,
// and chi-friendly middleware. Storage backends include in-memory and Postgres
// (pgx + sqlc). OAuth providers, TOTP, WebAuthn, and MCP OAuth 2.1 land in
// future versions; see the README roadmap.
package theauth
```

Replace with:

```go
// Package theauth provides OAuth 2.1 and MCP authorization for Go
// applications, alongside magic-link, email/password, WebAuthn passkey,
// TOTP, SAML, and SCIM authentication.
//
// TheAuth ships an OAuth 2.1 authorization server (PKCE-mandatory
// authorization code, client_credentials, refresh token rotation, RFC 8693
// token exchange, CIBA, PAR, JAR, DPoP-bound tokens), RFC 9728 MCP resource
// server metadata, agent identities with revocable delegation chains,
// organization-scoped RBAC, and an async audit log. Storage backends
// include in-memory, Postgres (pgx), and MySQL. See docs/AGENTS.md or
// https://theauth.dev for the full feature list and quick start.
package theauth
```

- [ ] **Step 2: Verify it builds and go vet is clean**

Run: `go build ./... && go vet ./.`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add doc.go
git commit -m "docs: fix stale doc.go claiming shipped features are future work"
```

---

### Task 2: Fix the Postgres `UpdateAgentLastActive` ErrNotFound divergence

**Files:**
- Modify: `storage/postgres/postgres_v20_agents.go:128-132`
- Modify: `storage/postgres/postgres_test.go` (add regression subtest inside `TestPostgresStoreContract`)

**Context:** `memory.Store.UpdateAgentLastActive` (`storage/memory/memory_v20.go:363`) returns `storage.ErrNotFound` when the agent doesn't exist. The Postgres version doesn't check `RowsAffected()` at all, so it silently succeeds. The sibling method `UpdateAgentStatus` two functions above it in the same file already has the correct pattern — copy it.

- [ ] **Step 1: Fix the bug**

Current code (`storage/postgres/postgres_v20_agents.go:128-132`):

```go
func (s *Store) UpdateAgentLastActive(ctx context.Context, id theauth.ULID, at time.Time) error {
	const q = `UPDATE agents SET last_active_at = $2 WHERE id = $1`
	_, err := s.pool.Exec(ctx, q, ulidToPgUUID(id), timeToTs(at))
	return err
}
```

Replace with:

```go
func (s *Store) UpdateAgentLastActive(ctx context.Context, id theauth.ULID, at time.Time) error {
	const q = `UPDATE agents SET last_active_at = $2 WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, ulidToPgUUID(id), timeToTs(at))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}
```

- [ ] **Step 2: Add the regression subtest**

In `storage/postgres/postgres_test.go`, inside `TestPostgresStoreContract`, right after the `storagetest.Run(t, store)` line, add:

```go
	t.Run("UpdateAgentLastActiveUnknownID", func(t *testing.T) {
		if err := store.UpdateAgentLastActive(context.Background(), ulid.New(), time.Now()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
```

(`context`, `errors`, `storage`, `time`, and `ulid` are already imported in this file — no import changes needed.)

- [ ] **Step 3: Run the test to verify it passes**

Requires a local Postgres. If you have Docker:

```bash
docker run -d --name theauth-pg-test -e POSTGRES_USER=theauth -e POSTGRES_PASSWORD=theauth -e POSTGRES_DB=theauth_test -p 5432:5432 postgres:16
sleep 3
THEAUTH_PG_CONTRACT=1 POSTGRES_TEST_URL='postgres://theauth:theauth@localhost:5432/theauth_test?sslmode=disable' go test ./storage/postgres/... -run TestPostgresStoreContract -v
docker rm -f theauth-pg-test
```

Expected: `PASS`, including the new `UpdateAgentLastActiveUnknownID` subtest.

- [ ] **Step 4: Commit**

```bash
git add storage/postgres/postgres_v20_agents.go storage/postgres/postgres_test.go
git commit -m "fix(storage/postgres): return ErrNotFound from UpdateAgentLastActive on missing row"
```

---

### Task 3: Fix six MySQL ErrNotFound divergences

**Files:**
- Modify: `storage/mysql/sessions.go` (`UpdateSessionAuthLevel`, `SetSessionActiveOrganization`)
- Modify: `storage/mysql/saml.go` (`UpdateSAMLConnectionRow`)
- Modify: `storage/mysql/scim.go` (`UpdateGroup`)
- Modify: `storage/mysql/agents.go` (`UpdateAgentLastActive`, `UpdateAgentCredentialLastUsed`)
- Modify: `storage/mysql/mysql_test.go` (add regression subtests inside `TestMySQLStoreContract`)

**Context:** Same class of bug as Task 2, six more instances, all confirmed against `storage/memory/*.go` returning `storage.ErrNotFound` for the equivalent method. `UpdateAgentStatus` in `storage/mysql/agents.go` already has the correct pattern (checks `res.RowsAffected()`) — every fix below copies it.

- [ ] **Step 1: Fix `UpdateSessionAuthLevel` and `SetSessionActiveOrganization`**

In `storage/mysql/sessions.go`, current code:

```go
func (s *Store) UpdateSessionAuthLevel(ctx context.Context, id theauth.ULID, level string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET auth_level = ? WHERE id = ?`,
		level,
		ulidToBytes(id),
	)
	return err
}

func (s *Store) SetSessionActiveOrganization(ctx context.Context, sessionID theauth.ULID, orgID *theauth.ULID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET active_organization_id = ? WHERE id = ?`,
		ulidPtrToBytes(orgID),
		ulidToBytes(sessionID),
	)
	return err
}
```

Replace with:

```go
func (s *Store) UpdateSessionAuthLevel(ctx context.Context, id theauth.ULID, level string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET auth_level = ? WHERE id = ?`,
		level,
		ulidToBytes(id),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) SetSessionActiveOrganization(ctx context.Context, sessionID theauth.ULID, orgID *theauth.ULID) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET active_organization_id = ? WHERE id = ?`,
		ulidPtrToBytes(orgID),
		ulidToBytes(sessionID),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}
```

- [ ] **Step 2: Fix `UpdateSAMLConnectionRow`**

In `storage/mysql/saml.go`, current code:

```go
func (s *Store) UpdateSAMLConnectionRow(ctx context.Context, c theauth.SAMLConnection) error {
	attrMap, err := json.Marshal(c.AttributeMap)
	if err != nil {
		return err
	}
	if string(attrMap) == "null" {
		attrMap = []byte("{}")
	}
	_, err = s.db.ExecContext(ctx, `
UPDATE saml_connections SET
    idp_entity_id = ?, idp_sso_url = ?, idp_x509_cert = ?,
    sp_entity_id = ?, sp_acs_url = ?,
    attribute_map = ?, updated_at = ?
WHERE id = ?`,
		c.IdPEntityID, c.IdPSSOURL, c.IdPX509Cert,
		c.SPEntityID, c.SPACSURL,
		attrMap, timeUTC(time.Now()),
		ulidToBytes(c.ID),
	)
	return err
}
```

Replace with:

```go
func (s *Store) UpdateSAMLConnectionRow(ctx context.Context, c theauth.SAMLConnection) error {
	attrMap, err := json.Marshal(c.AttributeMap)
	if err != nil {
		return err
	}
	if string(attrMap) == "null" {
		attrMap = []byte("{}")
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE saml_connections SET
    idp_entity_id = ?, idp_sso_url = ?, idp_x509_cert = ?,
    sp_entity_id = ?, sp_acs_url = ?,
    attribute_map = ?, updated_at = ?
WHERE id = ?`,
		c.IdPEntityID, c.IdPSSOURL, c.IdPX509Cert,
		c.SPEntityID, c.SPACSURL,
		attrMap, timeUTC(time.Now()),
		ulidToBytes(c.ID),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}
```

- [ ] **Step 3: Fix `UpdateGroup`**

In `storage/mysql/scim.go`, current code:

```go
func (s *Store) UpdateGroup(ctx context.Context, g theauth.Group) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE `+"`groups`"+` SET display_name = ?, external_id = ?, updated_at = ? WHERE id = ?`,
		g.DisplayName, nullStringVal(g.ExternalID), timeUTC(time.Now()), ulidToBytes(g.ID),
	)
	return err
}
```

Replace with:

```go
func (s *Store) UpdateGroup(ctx context.Context, g theauth.Group) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE `+"`groups`"+` SET display_name = ?, external_id = ?, updated_at = ? WHERE id = ?`,
		g.DisplayName, nullStringVal(g.ExternalID), timeUTC(time.Now()), ulidToBytes(g.ID),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}
```

- [ ] **Step 4: Fix `UpdateAgentLastActive` and `UpdateAgentCredentialLastUsed`**

In `storage/mysql/agents.go`, current code:

```go
func (s *Store) UpdateAgentLastActive(ctx context.Context, id theauth.ULID, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_active_at = ? WHERE id = ?`,
		timeUTC(at), ulidToBytes(id),
	)
	return err
}
```

Replace with:

```go
func (s *Store) UpdateAgentLastActive(ctx context.Context, id theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_active_at = ? WHERE id = ?`,
		timeUTC(at), ulidToBytes(id),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}
```

And current code:

```go
func (s *Store) UpdateAgentCredentialLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agent_credentials SET last_used_at = ? WHERE id = ?`,
		timeUTC(at), ulidToBytes(id),
	)
	return err
}
```

Replace with:

```go
func (s *Store) UpdateAgentCredentialLastUsed(ctx context.Context, id theauth.ULID, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agent_credentials SET last_used_at = ? WHERE id = ?`,
		timeUTC(at), ulidToBytes(id),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}
```

- [ ] **Step 5: Add regression subtests**

In `storage/mysql/mysql_test.go`, update the import block from:

```go
import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	_ "github.com/go-sql-driver/mysql"

	"github.com/glincker/theauth-go/storage/mysql"
	"github.com/glincker/theauth-go/storagetest"
)
```

to:

```go
import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage"
	"github.com/glincker/theauth-go/storage/mysql"
	"github.com/glincker/theauth-go/storagetest"
)
```

Then, inside `TestMySQLStoreContract`, right after the `storagetest.Run(t, store)` line, add:

```go
	t.Run("UpdateSessionAuthLevelUnknownID", func(t *testing.T) {
		if err := store.UpdateSessionAuthLevel(ctx, ulid.New(), "full"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("SetSessionActiveOrganizationUnknownID", func(t *testing.T) {
		if err := store.SetSessionActiveOrganization(ctx, ulid.New(), nil); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("UpdateSAMLConnectionRowUnknownID", func(t *testing.T) {
		if err := store.UpdateSAMLConnectionRow(ctx, theauth.SAMLConnection{ID: ulid.New()}); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("UpdateGroupUnknownID", func(t *testing.T) {
		if err := store.UpdateGroup(ctx, theauth.Group{ID: ulid.New()}); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("UpdateAgentLastActiveUnknownID", func(t *testing.T) {
		if err := store.UpdateAgentLastActive(ctx, ulid.New(), time.Now()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("UpdateAgentCredentialLastUsedUnknownID", func(t *testing.T) {
		if err := store.UpdateAgentCredentialLastUsed(ctx, ulid.New(), time.Now()); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
```

- [ ] **Step 6: Run the test to verify it passes**

Requires a local MySQL. If you have Docker:

```bash
docker run -d --name theauth-mysql-test -e MYSQL_ROOT_PASSWORD=theauth -e MYSQL_DATABASE=theauth_test -p 3306:3306 mysql:8
sleep 15
THEAUTH_MYSQL_CONTRACT=1 THEAUTH_TEST_MYSQL_DSN='root:theauth@tcp(localhost:3306)/theauth_test?parseTime=true&loc=UTC' go test ./storage/mysql/... -run TestMySQLStoreContract -v
docker rm -f theauth-mysql-test
```

Expected: `PASS`, including all six new subtests.

- [ ] **Step 7: Commit**

```bash
git add storage/mysql/sessions.go storage/mysql/saml.go storage/mysql/scim.go storage/mysql/agents.go storage/mysql/mysql_test.go
git commit -m "fix(storage/mysql): return ErrNotFound from six UPDATE methods on missing row"
```

---

### Task 4: Add a MySQL service container to CI (infrastructure only, gates stay opt-in)

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `storage/postgres/postgres_test.go` (update stale comment)

**Context — rescoped after live verification (2026-07-13):** Running the full `TestPostgresStoreContract` against a live Postgres revealed the suite fails far beyond the single divergence fixed in Task 2 — NOT NULL constraint violations (`agents.scope_grant`, `webauthn_credentials.aaguid`), foreign-key violations (`delegation_grants`, `audit_events`), and cascading not-found errors across the Agents, Delegations, WebAuthn, AuthorizationCodes, RefreshTokens, and JWKSKeys domains. This points to `storagetest`'s shared fixtures not populating fields/rows that Postgres enforces but the lenient memory backend doesn't — a real but much larger fix than originally scoped, requiring its own dedicated investigation across every domain. MySQL's status is unverified (a live-verification attempt hit a Docker/networking issue in this environment before it could be confirmed either way), but given it's newer (added v2.4) and already at 0% coverage, assume it likely has comparable gaps rather than gambling on it being clean.

**Decision:** do NOT flip either `THEAUTH_PG_CONTRACT` or `THEAUTH_MYSQL_CONTRACT` to always-on in CI this round — that would turn CI red. Instead, add the MySQL service container as infrastructure (so a future task can flip its gate on the moment MySQL's divergences are fixed, without needing to touch CI again), leave both gates opt-in exactly as they are today, and correct the stale comment so it reflects what's actually known.

- [ ] **Step 1: Add the MySQL service container (gates stay opt-in — do not add `THEAUTH_PG_CONTRACT` or `THEAUTH_MYSQL_CONTRACT` env vars in this step)**

Current `test` job in `.github/workflows/ci.yml`:

```yaml
  test:
    if: github.event_name != 'schedule'
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: theauth
          POSTGRES_PASSWORD: theauth
          POSTGRES_DB: theauth_test
        ports: ["5432:5432"]
        options: >-
          --health-cmd "pg_isready -U theauth"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - run: go vet ./...
      - run: go test -race -timeout=120s -coverprofile=coverage.out ./...
        env:
          POSTGRES_TEST_URL: postgres://theauth:theauth@localhost:5432/theauth_test?sslmode=disable
      - run: go test -bench=. -benchmem -run=^$ -benchtime=1x ./internal/bench/...
```

Replace with:

```yaml
  test:
    if: github.event_name != 'schedule'
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: theauth
          POSTGRES_PASSWORD: theauth
          POSTGRES_DB: theauth_test
        ports: ["5432:5432"]
        options: >-
          --health-cmd "pg_isready -U theauth"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      mysql:
        image: mysql:8
        env:
          MYSQL_ROOT_PASSWORD: theauth
          MYSQL_DATABASE: theauth_test
        ports: ["3306:3306"]
        options: >-
          --health-cmd "mysqladmin ping -proot"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - run: go vet ./...
      - run: go test -race -timeout=120s -coverprofile=coverage.out ./...
        env:
          POSTGRES_TEST_URL: postgres://theauth:theauth@localhost:5432/theauth_test?sslmode=disable
      - run: go test -bench=. -benchmem -run=^$ -benchtime=1x ./internal/bench/...
```

Note what did NOT change: no `THEAUTH_PG_CONTRACT`, `THEAUTH_MYSQL_CONTRACT`, or `THEAUTH_TEST_MYSQL_DSN` env vars were added. The MySQL service now runs in CI and is reachable at `localhost:3306` for any developer who wants to opt in locally by re-running with those env vars set, but nothing in the default CI run exercises it yet. That's intentional — see Context above.

- [ ] **Step 2: Fix the stale comment above `TestPostgresStoreContract`**

In `storage/postgres/postgres_test.go`, the comment directly above `TestPostgresStoreContract` currently reads (approximately — read the actual current text, Task 2 may have left it unchanged):

```go
// TestPostgresStoreContract runs the full storagetest contract suite against
// the Postgres backend. Opt in by setting THEAUTH_PG_CONTRACT=1 alongside
// THEAUTH_TEST_PG_DSN. The Postgres backend currently has known divergences
// from the contract (operations on missing rows return nil rather than
// ErrNotFound on a handful of UPDATE/DELETE paths). Tracked for a follow-up
// hardening PR; the contract suite stays authoritative against the memory
// backend in CI today.
```

Replace the parenthetical with an accurate description of the actual, larger scope found on 2026-07-13:

```go
// TestPostgresStoreContract runs the full storagetest contract suite against
// the Postgres backend. Opt in by setting THEAUTH_PG_CONTRACT=1 alongside
// THEAUTH_TEST_PG_DSN. The Postgres backend currently fails this suite
// beyond the UpdateAgentLastActive divergence fixed in v2.5.x: NOT NULL
// constraint violations (agents.scope_grant, webauthn_credentials.aaguid),
// foreign-key violations (delegation_grants, audit_events), and cascading
// not-found errors across Agents, Delegations, WebAuthn, AuthorizationCodes,
// RefreshTokens, and JWKSKeys — likely storagetest fixtures not populating
// fields/rows Postgres enforces but the lenient memory backend doesn't.
// Tracked as dedicated follow-up work (see ROADMAP.md); the contract suite
// stays authoritative against the memory backend in CI today.
```

- [ ] **Step 3: Verify the workflow YAML is still valid and the job otherwise behaves as before**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`
Expected: no output (valid YAML).

Then push to a branch and confirm the `test` job still passes in GitHub Actions (it should behave identically to before except for the new idle `mysql` service container) before merging.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml storage/postgres/postgres_test.go
git commit -m "ci: add MySQL service container to CI (opt-in gates unchanged; see ROADMAP.md)"
```

---

### Task 5: RBAC edge-case coverage — `DeleteRole`, `UpdateRole`, `RevokeRole`

**Files:**
- Modify: `internal/rbac/service_rbac_test.go`

**Context:** `DeleteRole` has zero test coverage today — not even a happy path. `UpdateRole` and `RevokeRole` are only tested via the happy path in `TestPermissionMatrix`. This closes the biggest gaps in `internal/rbac`'s 43.8% coverage.

- [ ] **Step 1: Add the tests**

Append to `internal/rbac/service_rbac_test.go`:

```go
func TestRevokeRoleUnknownRole(t *testing.T) {
	fx := newRBACFixture(t)
	actor := internalulid.New()
	err := fx.auth.RevokeRole(fx.ctx, actor, fx.userID, internalulid.New())
	if !errors.Is(err, theauth.ErrStorageNotFound) {
		t.Fatalf("expected ErrStorageNotFound, got %v", err)
	}
}

func TestUpdateRoleUnknownRole(t *testing.T) {
	fx := newRBACFixture(t)
	_, err := fx.auth.UpdateRole(fx.ctx, internalulid.New(), "new-name", "desc", nil)
	if !errors.Is(err, theauth.ErrStorageNotFound) {
		t.Fatalf("expected ErrStorageNotFound, got %v", err)
	}
}

func TestDeleteRoleUnknownRole(t *testing.T) {
	fx := newRBACFixture(t)
	err := fx.auth.DeleteRole(fx.ctx, internalulid.New())
	if !errors.Is(err, theauth.ErrStorageNotFound) {
		t.Fatalf("expected ErrStorageNotFound, got %v", err)
	}
}

func TestDeleteRoleRemovesCustomRole(t *testing.T) {
	fx := newRBACFixture(t)
	role, err := fx.auth.CreateRole(fx.ctx, fx.orgID, "custom-readonly", "read only", []string{theauth.PermissionUsersRead})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := fx.auth.DeleteRole(fx.ctx, role.ID); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	got, err := fx.store.RoleByID(fx.ctx, role.ID)
	if err != nil {
		t.Fatalf("RoleByID after delete should not error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected role to be gone after DeleteRole, got %+v", got)
	}
}

func TestDeleteRoleBlockedWhenSoleUsersAdminGrantor(t *testing.T) {
	fx := newRBACFixture(t)
	actor := internalulid.New()
	adminRole := fx.roles[theauth.OrgRoleAdmin]
	if err := fx.auth.GrantRole(fx.ctx, actor, fx.userID, adminRole.ID); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	err := fx.auth.DeleteRole(fx.ctx, adminRole.ID)
	if !errors.Is(err, theauth.ErrRoleInUse) {
		t.Fatalf("expected ErrRoleInUse, got %v", err)
	}
}
```

(`errors`, `theauth`, and `internalulid` are already imported in this file — no import changes needed.)

- [ ] **Step 2: Run the tests**

Run: `go test ./internal/rbac/... -v -run 'TestRevokeRoleUnknownRole|TestUpdateRoleUnknownRole|TestDeleteRoleUnknownRole|TestDeleteRoleRemovesCustomRole|TestDeleteRoleBlockedWhenSoleUsersAdminGrantor'`
Expected: `PASS` for all five.

- [ ] **Step 3: Check coverage improved**

Run: `go test ./internal/rbac/... -cover`
Expected: coverage percentage higher than the baseline 43.8%.

- [ ] **Step 4: Commit**

```bash
git add internal/rbac/service_rbac_test.go
git commit -m "test(rbac): cover DeleteRole, and not-found paths for UpdateRole/RevokeRole"
```

---

### Task 6: WebAuthn `DeleteCredential` / `ListCredentials` coverage

**Files:**
- Create: `internal/webauthn/service_credentials_test.go`

**Context:** `Service.DeleteCredential` and `Service.ListCredentials` are only reachable via `internal/webauthn/handlers` today, never unit-tested directly — that's the biggest hole in `internal/webauthn`'s 43.8% coverage. This must be an **external test package** (`webauthn_test`, matching the existing `service_webauthn_test.go` in the same directory) that imports both `internal/webauthn` and `storage/memory` directly — an internal (`package webauthn`) test file can't do this, since `storage/memory` imports the root `theauth` package, which itself imports `internal/webauthn`, which would be an import cycle for an internal test file.

- [ ] **Step 1: Write the test file**

Create `internal/webauthn/service_credentials_test.go`:

```go
package webauthn_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/audit"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/internal/webauthn"
	"github.com/glincker/theauth-go/storage"
	"github.com/glincker/theauth-go/storage/memory"
)

// TestServiceListAndDeleteCredential exercises the two Service methods only
// reachable today via internal/webauthn/handlers: list-by-owner and
// delete-scoped-to-owner. cfg is nil since no real WebAuthn ceremony is
// exercised, only storage passthrough.
func TestServiceListAndDeleteCredential(t *testing.T) {
	store := memory.New()
	svc, err := webauthn.NewService(store, nil, audit.NoopEmitter{}, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx := context.Background()

	owner, err := store.CreateUser(ctx, theauth.User{
		ID: ulid.New(), Email: "owner@h.com",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	cred, err := store.InsertWebAuthnCredential(ctx, theauth.WebAuthnCredential{
		ID: ulid.New(), UserID: owner.ID, CredentialID: []byte("cred-1"),
		PublicKey: []byte("pk"), Name: "laptop", SignCount: 1, CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("InsertWebAuthnCredential: %v", err)
	}

	got, err := svc.ListCredentials(ctx, owner.ID)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(got) != 1 || got[0].ID != cred.ID {
		t.Fatalf("expected 1 credential owned by user, got %+v", got)
	}

	other := ulid.New()
	if err := svc.DeleteCredential(ctx, cred.ID, other); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound deleting another user's credential, got %v", err)
	}

	if err := svc.DeleteCredential(ctx, cred.ID, owner.ID); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	got, err = svc.ListCredentials(ctx, owner.ID)
	if err != nil {
		t.Fatalf("ListCredentials after delete: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no credentials after delete, got %d", len(got))
	}
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./internal/webauthn/... -v -run TestServiceListAndDeleteCredential`
Expected: `PASS`.

- [ ] **Step 3: Check coverage improved**

Run: `go test ./internal/webauthn/... -cover`
Expected: coverage percentage higher than the baseline 43.8%.

- [ ] **Step 4: Commit**

```bash
git add internal/webauthn/service_credentials_test.go
git commit -m "test(webauthn): cover Service.ListCredentials and Service.DeleteCredential"
```

---

### Task 7: Add a CodeQL workflow

**Files:**
- Create: `.github/workflows/codeql.yml`

- [ ] **Step 1: Write the workflow**

```yaml
name: codeql

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 8 * * 3"
  workflow_dispatch:

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: go
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
```

- [ ] **Step 2: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/codeql.yml'))"`
Expected: no output (valid YAML). If `python3`/`yaml` isn't available, `cat .github/workflows/codeql.yml` and visually confirm indentation matches the other workflow files in `.github/workflows/`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/codeql.yml
git commit -m "ci: add CodeQL static analysis workflow"
```

Push to a branch afterward and confirm the `codeql` workflow run succeeds in the Actions tab before merging — this is real infra behavior a local syntax check can't fully verify.

---

### Task 8: Add Dependabot configuration

**Files:**
- Create: `.github/dependabot.yml`

- [ ] **Step 1: Write the config**

```yaml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10

  - package-ecosystem: "gomod"
    directory: "/mcpresource"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

- [ ] **Step 2: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/dependabot.yml'))"`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add .github/dependabot.yml
git commit -m "ci: add Dependabot config for gomod and github-actions ecosystems"
```

---

### Task 9: Add root and docs-site `llms.txt`

**Files:**
- Create: `llms.txt`
- Create: `docs-site/docs/llms.txt`

**Context:** `docs/AGENTS.md` already has an accurate, versioned feature history. `llms.txt` (the emerging convention at `/llms.txt`, see llmstxt.org) is a distinct, more compact artifact: a single markdown file an LLM crawler checks first for a structured project summary with links. Both files get the same content; the docs-site copy is what makes it reachable at `https://theauth.dev/llms.txt` (MkDocs serves any non-markdown-processed file placed in `docs-site/docs/` verbatim — this is exactly how `docs-site/docs/CNAME` already works).

- [ ] **Step 1: Write `llms.txt`**

```markdown
# theauth-go

> Go library providing OAuth 2.1 authorization server, MCP (Model Context Protocol) authorization, agent identities with revocable delegation chains, and traditional authentication (magic-link, email/password, WebAuthn passkeys, TOTP, SAML, SCIM). Self-hosted, MIT licensed, single `go get` import.

theauth-go is not a SaaS or hosted IdP. It is a Go library you mount into your own `chi` or `net/http` server.

## Core capabilities

- OAuth 2.1: authorization code + mandatory PKCE S256, refresh token rotation with family revocation, client_credentials, RFC 8693 token exchange, RFC 9509 CIBA, RFC 9126 PAR, RFC 9101 JAR, RFC 9449 DPoP-bound tokens.
- MCP authorization: RFC 9728 OAuth 2.0 Protected Resource Metadata, CIMD per MCP spec 2025-11-25, a companion zero-dependency SDK module at `github.com/glincker/theauth-go/mcpresource`.
- Authentication: magic-link email, email/password (argon2id), WebAuthn/FIDO2 passkeys, TOTP with recovery codes, SAML 2.0 Service Provider, SCIM 2.0 provisioning.
- Agent identity: Agent + AgentCredential primitives, delegation grants, chain-depth-capped token exchange for AI agent use cases.
- Authorization: organization-scoped RBAC with seeded permissions and default roles.
- Storage: in-memory (tests), Postgres (pgx), MySQL. Pluggable `Storage` interface for custom backends.
- Observability: OpenTelemetry tracing, Prometheus metrics, structured audit log with pluggable sinks (webhook, Splunk HEC).

## Docs

- [README](https://github.com/glincker/theauth-go/blob/main/README.md): quick start, feature comparison table, examples index.
- [Full documentation](https://theauth.dev): getting started, concepts, guides, API reference.
- [AGENTS.md](https://github.com/glincker/theauth-go/blob/main/docs/AGENTS.md): version-by-version shipped feature history, written for AI coding assistants.
- [STABILITY.md](https://github.com/glincker/theauth-go/blob/main/docs/STABILITY.md): SemVer contract and API surface guarantees.
- [CHANGELOG](https://github.com/glincker/theauth-go/blob/main/CHANGELOG.md): release notes.
- [Migrating from Auth0](https://github.com/glincker/theauth-go/blob/main/docs/MIGRATING-FROM-AUTH0.md) / [Migrating from Cognito](https://github.com/glincker/theauth-go/blob/main/docs/MIGRATING-FROM-COGNITO.md).

## Quick start

```go
a, _ := theauth.New(theauth.Config{
    Storage: memory.New(),
    BaseURL: "http://localhost:8080",
})
r := chi.NewRouter()
a.Mount(r) // /auth/* magic-link, email-password, OAuth, passkeys, TOTP, SAML
```

`go get github.com/glincker/theauth-go`. Requires Go 1.25+.
```

- [ ] **Step 2: Copy the same content to the docs site**

```bash
cp llms.txt docs-site/docs/llms.txt
```

- [ ] **Step 3: Verify the docs-site build still succeeds locally**

Run: `cd docs-site && pip install -r requirements.txt -q && mkdocs build --strict && cd ..`
Expected: build succeeds (mkdocs should treat the new file as a static passthrough, same as `CNAME`).

- [ ] **Step 4: Commit**

```bash
git add llms.txt docs-site/docs/llms.txt
git commit -m "docs: add llms.txt for LLM-crawler discoverability"
```

---

### Task 10: Add `ROADMAP.md`

**Files:**
- Create: `ROADMAP.md`

**Context:** Source content from `CHANGELOG.md`'s `v2.5.0-rc.1` entry (the hook-wiring items explicitly deferred to "subsequent v2.5.x patches" and the "#79 selective re-exports" item) plus what's already shipped in recent commits (`OnOAuthConflict`, `IssueSessionByUserID`, `LinkOAuthProviderBySession`, `UnlinkOAuthProvider` per `git log`). Also documents the storage-contract-suite scope discovered while executing this plan (Task 4 rescope, 2026-07-13): the Postgres backend fails `TestPostgresStoreContract` well beyond the one divergence fixed in Task 2 (NOT NULL/FK violations and cascading not-found errors across Agents, Delegations, WebAuthn, AuthorizationCodes, RefreshTokens, JWKSKeys), and MySQL's status against the same suite is unverified. This is real follow-up work, not something this plan closes out.

- [ ] **Step 1: Write `ROADMAP.md`**

```markdown
# Roadmap

This is the living, human-readable version of what's in flight. The
authoritative record of what's shipped is [CHANGELOG.md](CHANGELOG.md);
this file is forward-looking and gets pruned as items land.

## Now (v2.5.x)

Continuing the `Config.LifecycleHooks` surface introduced in v2.5.0-rc.1.
Shipped so far: `OnSignup`, `OnSignin` (password, magic-link, OAuth
callback paths), `OnOAuthConflict`, plus the `IssueSessionByUserID` /
`LinkOAuthProviderBySession` / `UnlinkOAuthProvider` forwarders that
support custom OAuth-conflict resolution flows.

Remaining hook wiring, landing incrementally without API changes:

- [ ] Passkey and SAML signup paths call `OnSignup`
- [ ] `OnPasswordChange`
- [ ] `OnMFAEnabled`
- [ ] `OnTokenIssued`
- [ ] `OnOrgSwitch`
- [ ] Selective package re-exports (#79) so consumers can import fewer
      symbols from the root package

## Stability hardening (in progress)

- [x] Fix 7 confirmed Postgres/MySQL storage methods silently succeeding on
      missing-row updates instead of returning `ErrNotFound`
- [x] MySQL service container available in CI (opt-in contract gate, not
      yet enabled by default)
- [x] Dependency and static-analysis scanning (Dependabot, CodeQL)
- [ ] Raise `internal/rbac` and `internal/webauthn` unit coverage further
      beyond the DeleteRole/DeleteCredential gaps closed in this pass
- [ ] **Full storage-contract-suite parity (bigger, separate effort).**
      `TestPostgresStoreContract` fails well beyond the fixes above: NOT
      NULL constraint violations (`agents.scope_grant`,
      `webauthn_credentials.aaguid`), foreign-key violations
      (`delegation_grants`, `audit_events`), and cascading not-found
      errors across Agents, Delegations, WebAuthn, AuthorizationCodes,
      RefreshTokens, and JWKSKeys. Likely root cause: `storagetest`'s
      shared fixtures don't populate fields/rows Postgres enforces but
      the lenient memory backend doesn't. MySQL's status against the
      same suite is unverified. Needs its own dedicated investigation
      per domain before `THEAUTH_PG_CONTRACT`/`THEAUTH_MYSQL_CONTRACT`
      can be turned on by default in CI.

## Under consideration

Nothing else is committed yet. Feature requests and discussion happen in
[GitHub Discussions](https://github.com/glincker/theauth-go/discussions);
raised items get added here once there's a concrete plan.
```

- [ ] **Step 2: Cross-check against CHANGELOG**

Run: `grep -A3 '^## \[Unreleased\]' CHANGELOG.md` and `git log --oneline -10`
Expected: confirm no shipped item from the last 10 commits or the Unreleased section is missing from `ROADMAP.md`'s "Now" list; add any that are.

- [ ] **Step 3: Commit**

```bash
git add ROADMAP.md
git commit -m "docs: add ROADMAP.md making in-flight work explicit"
```

---

### Task 11: README polish — coverage badge and FAQ

**Files:**
- Modify: `.github/workflows/ci.yml` (upload coverage)
- Modify: `README.md`

- [ ] **Step 1: Upload coverage to Codecov from CI**

In `.github/workflows/ci.yml`, in the `test` job, add a step right after the `go test -race ...` step (which already produces `coverage.out`):

```yaml
      - uses: codecov/codecov-action@v5
        with:
          files: coverage.out
          fail_ci_if_error: false
```

Note for the engineer: Codecov's tokenless upload works for most public GitHub repos, but if uploads start failing in Actions logs, a `CODECOV_TOKEN` repo secret needs to be added at https://app.codecov.io — that's a manual step outside this plan's scope (repo settings), flag it to the user rather than trying to work around it.

- [ ] **Step 2: Add the coverage badge to README**

In `README.md`, in the badge block (currently lines 16-24), add one line after the existing `CI` badge (line 20):

```markdown
[![codecov](https://codecov.io/gh/glincker/theauth-go/branch/main/graph/badge.svg)](https://codecov.io/gh/glincker/theauth-go)
```

- [ ] **Step 3: Add an FAQ section to README**

Add a new `## FAQ` section right before the `## Contributing` section (currently at line 309, per the `## Contents` list at line 48). Also add `- [FAQ](#faq)` to the `## Contents` list, right before `- [Contributing](#contributing)`.

```markdown
## FAQ

**Is this production ready?**
Yes for v1.0+ surfaces (session auth, OAuth providers, RBAC, audit log) —
covered by [STABILITY.md](docs/STABILITY.md)'s SemVer contract. v2.0's
OAuth 2.1 authorization server and agent-identity primitives are feature
complete as of v2.0.0 and used in production by early adopters; check
[CHANGELOG.md](CHANGELOG.md) for the current release.

**How does it compare to Auth0, better-auth, or Ory Hydra?**
See the [comparison table](#why-theauth-go) above. The short version:
theauth-go is self-hosted like better-auth/Hydra but also ships MCP
authorization and FAPI 2.0-adjacent features (PAR+JAR+DPoP) that none of
the alternatives have.

**Does it support AI agent / MCP use cases specifically?**
Yes — this is one of the two things that differentiate it from every
other Go auth library. See [MCP resource server](#mcp-resource-server)
below, and the agent-identity + delegation-chain docs.

**What databases are supported?**
Postgres and MySQL, plus an in-memory backend for tests. The `Storage`
interface is public, so custom backends are possible.

**Is it free and open source?**
Yes, MIT licensed, no paid tier gating any feature in this repository.
```

- [ ] **Step 4: Verify markdown renders correctly**

Run: `grep -c '^## ' README.md`
Expected: count increases by 1 versus before this change (confirms the new `## FAQ` heading was added without breaking existing headings).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml README.md
git commit -m "docs: add coverage badge and FAQ section to README"
```

---

## Final step: hand off the external-growth checklist

After all 11 tasks are merged, tell the user (do not act on any of these — they said they'll handle external/public moves themselves):

- Set GitHub repo topics (Settings → General → Topics): `oauth2`, `oidc`, `mcp`, `golang`, `authorization-server`, `passkeys`, etc. (mirror the keyword comment at the top of `README.md`).
- Submit a PR to [avelino/awesome-go](https://github.com/avelino/awesome-go) under the Authentication & Authorization section.
- Consider a "Show HN" post once the coverage badge is green and CodeQL/Dependabot have run at least once (so the repo looks active/maintained to anyone who clicks through).
- Consider naming `glinr-backend-v2` (or a generic "an in-house production service") in a "Used by" README section once comfortable making that public.
- An external blog post / dev.to writeup comparing theauth-go to Auth0/better-auth for the MCP-authorization angle specifically — that's the most differentiated story and the one most likely to get cited by AI assistants doing research.
