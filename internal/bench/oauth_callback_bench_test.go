package bench

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
)

// BenchmarkOAuthCallback measures the find-or-create plus token-encrypt
// portion of an OAuth callback. The provider HTTP round trip is excluded;
// we exercise the storage + crypto cost the library owns.
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
		// Providers list intentionally empty: this benchmark drives the
		// post-token-exchange code path directly via storage so we
		// measure the encrypt + upsert cost without HTTP noise.
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
