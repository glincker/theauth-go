// Package storagetest provides a public contract test suite for theauth.Storage
// implementations.
//
// Any third-party storage backend (MySQL, DynamoDB, CockroachDB, etc.) can
// prove conformance with the theauth.Storage interface by calling Run from
// within a *_test.go file:
//
//	func TestMyBackendContract(t *testing.T) {
//	    store := mybackend.New(...)
//	    storagetest.Run(t, store)
//	}
//
// Passing all sub-tests guarantees the backend implements the documented
// semantics, not just the method signatures.
//
// # Contract guarantees tested
//
// The suite covers:
//   - User CRUD and email lookup
//   - Magic link create/consume (one-time, expiry rejected)
//   - Password credential set/get/update
//   - WebAuthn credential register, sign-count, replay detection, delete
//   - TOTP secret pending/confirm/delete lifecycle
//   - OAuth client CRUD and nil-slice coercion (#40)
//   - Authorization code single-use atomicity
//   - Refresh token insert/lookup/revoke/family revocation
//   - JWKS key insert/state transitions
//   - Agent lifecycle: create/list/suspend/resume/revoke
//   - Delegation grant create/lookup/revoke
//   - Audit event insert (single + batch) and query with pagination
//   - RBAC role/permission CRUD and user-role grants
//   - Session create/lookup/revoke/auth-level promotion
//
// # Fresh store contract
//
// Run accepts a fresh storage instance with no existing rows. The suite does
// not reset state between domains; each domain test receives the same store
// and must create its own data with unique identifiers. Callers that want
// full isolation should wrap Run in a sub-test with its own fresh store:
//
//	t.Run("Contract", func(t *testing.T) {
//	    storagetest.Run(t, mybackend.New(...))
//	})
//
// # Optional interfaces
//
// Some storage methods are grouped in optional extension interfaces
// (e.g., theauth.OAuthServerStorage). When a backend does not implement
// the extension the relevant sub-tests are skipped with t.Skip so the
// core contract still runs.
package storagetest
