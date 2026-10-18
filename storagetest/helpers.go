package storagetest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/oklog/ulid/v2"
)

// newID returns a fresh ULID using crypto/rand.
func newID() theauth.ULID {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader)
}

// sha256Hash returns the SHA-256 digest of b as a byte slice.
func sha256Hash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// ensureUser creates a user through the store's own API and returns its id,
// so contract cases that reference a user stay valid on backends that enforce
// foreign keys. A store that does not implement theauth.UserStorage gets a
// bare random id (such a backend has no users table to reference).
func ensureUser(t *testing.T, store any, emailPrefix string) theauth.ULID {
	t.Helper()
	id := newID()
	us, ok := store.(theauth.UserStorage)
	if !ok {
		return id
	}
	if _, err := us.CreateUser(context.Background(), theauth.User{
		ID:        id,
		Email:     emailPrefix + "-" + id.String() + "@storagetest.example",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("ensureUser CreateUser: %v", err)
	}
	return id
}

// ensureOAuthClient inserts an OAuth client with the given client id so rows
// that reference it (authorization codes, refresh tokens) satisfy foreign keys.
func ensureOAuthClient(t *testing.T, store theauth.OAuthServerStorage, clientID string) {
	t.Helper()
	if _, err := store.InsertOAuthClient(context.Background(), theauth.OAuthClient{
		ID:                      newID(),
		ClientID:                clientID,
		ClientName:              "Storagetest " + clientID,
		RedirectURIs:            []string{"https://example.com/callback"},
		GrantTypes:              []string{theauth.GrantTypeAuthorizationCode},
		ResponseTypes:           []string{theauth.ResponseTypeCode},
		Scope:                   "openid",
		TokenEndpointAuthMethod: theauth.ClientAuthSecretBasic,
		CreatedAt:               time.Now(),
	}); err != nil {
		t.Fatalf("ensureOAuthClient InsertOAuthClient: %v", err)
	}
}

// ensureAgent inserts an agent owned by ownerID and returns its id, so rows
// that reference the agent (delegation grants) satisfy foreign keys.
func ensureAgent(t *testing.T, store theauth.OAuthServerStorage, ownerID theauth.ULID) theauth.ULID {
	t.Helper()
	clientID := "st-support-agent-client-" + newID().String()
	ensureOAuthClient(t, store, clientID)
	a, err := store.InsertAgent(context.Background(), theauth.Agent{
		ID:          newID(),
		OwnerUserID: &ownerID,
		Name:        "storagetest-support-agent-" + newID().String(),
		Status:      theauth.AgentStatusActive,
		ClientID:    clientID,
		Scope:       []string{"openid"},
		CreatedAt:   time.Now(),
	})
	if err != nil {
		t.Fatalf("ensureAgent InsertAgent: %v", err)
	}
	return a.ID
}
