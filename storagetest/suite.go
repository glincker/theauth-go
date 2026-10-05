package storagetest

import (
	"testing"

	"github.com/glincker/theauth-go/v2"
)

// SessionSuiteStorage is the storage RunCore's session tests need.
type SessionSuiteStorage interface {
	theauth.UserStorage
	theauth.SessionStorage
}

// PasswordSuiteStorage is the storage RunCore's password tests need.
type PasswordSuiteStorage interface {
	theauth.UserStorage
	theauth.PasswordStorage
}

// WebAuthnSuiteStorage is the storage RunWebAuthn needs.
type WebAuthnSuiteStorage interface {
	theauth.UserStorage
	theauth.WebAuthnStorage
}

// TOTPSuiteStorage is the storage RunTOTP needs.
type TOTPSuiteStorage interface {
	theauth.UserStorage
	theauth.TOTPStorage
}

// AuditSuiteStorage is the storage RunAudit needs.
type AuditSuiteStorage interface {
	theauth.UserStorage
	theauth.AuditStorage
}

// RBACSuiteStorage is the storage RunRBAC needs.
type RBACSuiteStorage interface {
	theauth.UserStorage
	theauth.RBACStorage
}

// RunCore runs the users, sessions, magic link and password contract tests
// against a theauth.CoreStorage.
func RunCore(t *testing.T, store theauth.CoreStorage) {
	t.Helper()
	t.Run("Users", func(t *testing.T) { testUsers(t, store) })
	t.Run("Sessions", func(t *testing.T) { testSessions(t, store) })
	t.Run("MagicLinks", func(t *testing.T) { testMagicLinks(t, store) })
	t.Run("Passwords", func(t *testing.T) { testPasswords(t, store) })
}

// RunWebAuthn runs the WebAuthn credential contract tests.
func RunWebAuthn(t *testing.T, store WebAuthnSuiteStorage) {
	t.Helper()
	t.Run("WebAuthn", func(t *testing.T) { testWebAuthnCredentials(t, store) })
}

// RunTOTP runs the TOTP secret and recovery code contract tests.
func RunTOTP(t *testing.T, store TOTPSuiteStorage) {
	t.Helper()
	t.Run("TOTP", func(t *testing.T) { testTOTPSecrets(t, store) })
}

// RunAudit runs the audit event contract tests.
func RunAudit(t *testing.T, store AuditSuiteStorage) {
	t.Helper()
	t.Run("AuditEvents", func(t *testing.T) { testAuditEvents(t, store) })
}

// RunRBAC runs the role and permission contract tests.
func RunRBAC(t *testing.T, store RBACSuiteStorage) {
	t.Helper()
	t.Run("Roles", func(t *testing.T) { testRoles(t, store) })
}

// RunOAuthServer runs the OAuth 2.1 authorization server contract tests:
// clients, authorization codes, refresh tokens, JWKS keys, agents and
// delegations.
func RunOAuthServer(t *testing.T, store theauth.OAuthServerStorage) {
	t.Helper()
	t.Run("OAuthClients", func(t *testing.T) { testOAuthClients(t, store) })
	t.Run("AuthorizationCodes", func(t *testing.T) { testAuthorizationCodes(t, store) })
	t.Run("RefreshTokens", func(t *testing.T) { testRefreshTokens(t, store) })
	t.Run("JWKSKeys", func(t *testing.T) { testJWKSKeys(t, store) })
	t.Run("Agents", func(t *testing.T) { testAgents(t, store) })
	t.Run("Delegations", func(t *testing.T) { testDelegations(t, store) })
}

// Run executes the full contract test suite against the given storage by
// calling every per-capability entry point. Pass a fresh storage instance
// (no rows).
//
// If the backend also implements theauth.OAuthServerStorage, the OAuth 2.1
// authorization server domains are included. Otherwise those sub-tests are
// skipped.
func Run(t *testing.T, store theauth.Storage) {
	t.Helper()

	RunCore(t, store)
	RunWebAuthn(t, store)
	RunTOTP(t, store)
	RunAudit(t, store)
	RunRBAC(t, store)

	if sm, ok := store.(SessionManagementSuiteStorage); ok {
		RunSessionManagement(t, sm)
	} else {
		t.Log("backend does not implement session management capabilities; skipping")
	}

	oauthStore, ok := store.(theauth.OAuthServerStorage)
	if !ok {
		t.Log("backend does not implement OAuthServerStorage; skipping OAuth AS sub-tests")
		return
	}
	RunOAuthServer(t, oauthStore)
}
