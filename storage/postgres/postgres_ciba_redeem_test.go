package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storagetest"
)

// TestPostgresCIBARedeemContract needs the Postgres test database; testPool
// skips when it is not configured.
func TestPostgresCIBARedeemContract(t *testing.T) {
	s := capsStore(t)
	// Postgres enforces backchannel_requests.client_id -> oauth_clients, so the
	// suite needs a real client row.
	seed := func(t *testing.T, clientID string) {
		t.Helper()
		_, err := s.InsertOAuthClient(context.Background(), theauth.OAuthClient{
			ID:                      ulid.New(),
			ClientID:                clientID,
			ClientName:              "CIBA redeem client",
			RedirectURIs:            []string{"https://example.com/callback"},
			GrantTypes:              []string{theauth.GrantTypeAuthorizationCode},
			ResponseTypes:           []string{theauth.ResponseTypeCode},
			Scope:                   "openid",
			TokenEndpointAuthMethod: theauth.ClientAuthSecretBasic,
			CreatedAt:               time.Now(),
		})
		if err != nil {
			t.Fatalf("seed client: %v", err)
		}
	}
	storagetest.RunCIBARedeem(t, s, storagetest.WithClientSeed(seed))
}
