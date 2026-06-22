package storagetest

import (
	"testing"

	"github.com/glincker/theauth-go"
)

// Run executes the full contract test suite against the given storage.
// Pass a fresh storage instance (no rows). Run will create, read, update,
// and delete across every domain the Storage interface supports.
//
// If the backend also implements theauth.OAuthServerStorage, the OAuth 2.1
// authorization server domains (OAuth clients, authorization codes, refresh
// tokens, JWKS keys, agents, delegations) are included. Otherwise those
// sub-tests are skipped.
func Run(t *testing.T, store theauth.Storage) {
	t.Helper()

	t.Run("Users", func(t *testing.T) { testUsers(t, store) })
	t.Run("Sessions", func(t *testing.T) { testSessions(t, store) })
	t.Run("MagicLinks", func(t *testing.T) { testMagicLinks(t, store) })
	t.Run("Passwords", func(t *testing.T) { testPasswords(t, store) })
	t.Run("WebAuthn", func(t *testing.T) { testWebAuthnCredentials(t, store) })
	t.Run("TOTP", func(t *testing.T) { testTOTPSecrets(t, store) })
	t.Run("AuditEvents", func(t *testing.T) { testAuditEvents(t, store) })
	t.Run("Roles", func(t *testing.T) { testRoles(t, store) })

	// OAuthServerStorage is an optional extension interface. Skip if not implemented.
	oauthStore, ok := store.(theauth.OAuthServerStorage)
	if !ok {
		t.Log("backend does not implement OAuthServerStorage; skipping OAuth AS sub-tests")
		return
	}
	t.Run("OAuthClients", func(t *testing.T) { testOAuthClients(t, oauthStore) })
	t.Run("AuthorizationCodes", func(t *testing.T) { testAuthorizationCodes(t, oauthStore) })
	t.Run("RefreshTokens", func(t *testing.T) { testRefreshTokens(t, oauthStore) })
	t.Run("JWKSKeys", func(t *testing.T) { testJWKSKeys(t, oauthStore) })
	t.Run("Agents", func(t *testing.T) { testAgents(t, oauthStore) })
	t.Run("Delegations", func(t *testing.T) { testDelegations(t, oauthStore) })
}
