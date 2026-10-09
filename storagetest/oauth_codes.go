package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

func testAuthorizationCodes(t *testing.T, store theauth.OAuthServerStorage) {
	t.Helper()
	ctx := context.Background()

	userID := newID()

	t.Run("InsertAndConsumeOnce", func(t *testing.T) {
		code := theauth.AuthorizationCode{
			Code:      "st-authz-code-" + newID().String(),
			ClientID:  "st-code-client",
			UserID:    userID,
			Scope:     []string{"openid"},
			ExpiresAt: time.Now().Add(60 * time.Second),
			CreatedAt: time.Now(),
		}
		if err := store.InsertAuthorizationCode(ctx, code); err != nil {
			t.Fatalf("InsertAuthorizationCode: %v", err)
		}

		got, err := store.ConsumeAuthorizationCode(ctx, code.Code)
		if err != nil {
			t.Fatalf("ConsumeAuthorizationCode (first): %v", err)
		}
		if got.ClientID != code.ClientID {
			t.Fatalf("ClientID mismatch")
		}

		// Second consume must miss.
		if _, err := store.ConsumeAuthorizationCode(ctx, code.Code); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("second consume: want ErrNotFound, got %v", err)
		}
	})

	t.Run("AuthorizationDetailsRoundTrip", func(t *testing.T) {
		code := theauth.AuthorizationCode{
			Code:                 "st-authz-rar-" + newID().String(),
			ClientID:             "st-code-client",
			UserID:               userID,
			Scope:                []string{"openid"},
			AuthorizationDetails: []byte(`[{"type":"payment","actions":["initiate"]}]`),
			ExpiresAt:            time.Now().Add(60 * time.Second),
			CreatedAt:            time.Now(),
		}
		if err := store.InsertAuthorizationCode(ctx, code); err != nil {
			t.Fatalf("InsertAuthorizationCode: %v", err)
		}
		got, err := store.ConsumeAuthorizationCode(ctx, code.Code)
		if err != nil {
			t.Fatalf("ConsumeAuthorizationCode: %v", err)
		}
		if string(normalizeJSON(got.AuthorizationDetails)) != string(normalizeJSON(code.AuthorizationDetails)) {
			t.Fatalf("authorization_details lost: %s", got.AuthorizationDetails)
		}
	})

	t.Run("MissingCodeRejected", func(t *testing.T) {
		if _, err := store.ConsumeAuthorizationCode(ctx, "no-such-code"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
}
