package bench

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

// BenchmarkOAuthCallback measures the find-or-create and token encryption cost of an OAuth
// callback, excluding the provider round trip.
func BenchmarkOAuthCallback(b *testing.B) {
	store := memory.New()
	key := make([]byte, crypto.AESKeyLen)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "http://localhost",
		EncryptionKey: key,
		// No providers are configured: the benchmark drives the post-exchange path directly through storage.
		SecureCookie: false,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(a.Close)
	ctx := context.Background()

	// Pre-create the user so the callback hits the linked-account branch.
	user, err := store.CreateUser(ctx, theauth.User{
		ID:        ulid.New(),
		Email:     "oauth-bench@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	if err != nil {
		b.Fatal(err)
	}

	accessToken := []byte("fake-access-token-value")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc, err := crypto.Encrypt(key, accessToken)
		if err != nil {
			b.Fatal(err)
		}
		_, err = store.UpsertOAuthAccount(ctx, theauth.OAuthAccount{
			ID:             ulid.New(),
			UserID:         user.ID,
			Provider:       "bench",
			ProviderUserID: "fixed-id",
			AccessTokenEnc: enc,
			Scope:          "read",
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}
