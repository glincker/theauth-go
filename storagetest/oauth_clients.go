package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

func testOAuthClients(t *testing.T, store theauth.OAuthServerStorage) {
	t.Helper()
	ctx := context.Background()

	clientID := "st-client-" + newID().String()

	t.Run("Insert", func(t *testing.T) {
		c := theauth.OAuthClient{
			ID:                      newID(),
			ClientID:                clientID,
			ClientName:              "Storagetest Client",
			RedirectURIs:            []string{"https://example.com/callback"},
			GrantTypes:              []string{theauth.GrantTypeAuthorizationCode},
			ResponseTypes:           []string{theauth.ResponseTypeCode},
			Scope:                   "openid profile",
			TokenEndpointAuthMethod: theauth.ClientAuthSecretBasic,
			CreatedAt:               time.Now(),
		}
		got, err := store.InsertOAuthClient(ctx, c)
		if err != nil {
			t.Fatalf("InsertOAuthClient: %v", err)
		}
		if got.ClientID != clientID {
			t.Fatalf("ClientID mismatch: want %q got %q", clientID, got.ClientID)
		}
	})

	t.Run("GetByClientID", func(t *testing.T) {
		got, err := store.OAuthClientByClientID(ctx, clientID)
		if err != nil {
			t.Fatalf("OAuthClientByClientID: %v", err)
		}
		if got.ClientName != "Storagetest Client" {
			t.Fatalf("ClientName mismatch: got %q", got.ClientName)
		}
	})

	t.Run("TokenPolicyRoundTrip", func(t *testing.T) {
		id := "st-policy-" + newID().String()
		_, err := store.InsertOAuthClient(ctx, theauth.OAuthClient{
			ID:                           newID(),
			ClientID:                     id,
			ClientName:                   "Policy Client",
			RedirectURIs:                 []string{"https://example.com/callback"},
			GrantTypes:                   []string{theauth.GrantTypeAuthorizationCode},
			ResponseTypes:                []string{theauth.ResponseTypeCode},
			TokenEndpointAuthMethod:      theauth.ClientAuthSecretBasic,
			AccessTokenFormat:            theauth.AccessTokenFormatOpaque,
			AccessTokenSignedResponseAlg: "ES256",
			AuthorizationDetailsTypes:    []string{"payment", "account"},
			CreatedAt:                    time.Now(),
		})
		if err != nil {
			t.Fatalf("InsertOAuthClient: %v", err)
		}
		got, err := store.OAuthClientByClientID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.AccessTokenFormat != theauth.AccessTokenFormatOpaque || got.AccessTokenSignedResponseAlg != "ES256" ||
			len(got.AuthorizationDetailsTypes) != 2 || got.AuthorizationDetailsTypes[0] != "payment" {
			t.Fatalf("token policy fields lost: %+v", got)
		}
		got.AccessTokenFormat = ""
		got.AuthorizationDetailsTypes = []string{"account"}
		if _, err := store.UpdateOAuthClient(ctx, *got); err != nil {
			t.Fatal(err)
		}
		again, err := store.OAuthClientByClientID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if again.AccessTokenFormat != "" || len(again.AuthorizationDetailsTypes) != 1 {
			t.Fatalf("update did not persist: %+v", again)
		}
	})

	t.Run("NilSliceCoercion", func(t *testing.T) {
		// Issue #40: backends must not return nil slices for array fields.
		got, err := store.OAuthClientByClientID(ctx, clientID)
		if err != nil {
			t.Fatalf("OAuthClientByClientID: %v", err)
		}
		if got.RedirectURIs == nil {
			t.Fatal("RedirectURIs must be a non-nil slice (nil coercion #40)")
		}
		if got.GrantTypes == nil {
			t.Fatal("GrantTypes must be a non-nil slice (nil coercion #40)")
		}
		if got.ResponseTypes == nil {
			t.Fatal("ResponseTypes must be a non-nil slice (nil coercion #40)")
		}
	})

	t.Run("Update", func(t *testing.T) {
		existing, err := store.OAuthClientByClientID(ctx, clientID)
		if err != nil {
			t.Fatalf("OAuthClientByClientID: %v", err)
		}
		existing.ClientName = "Updated Name"
		updated, err := store.UpdateOAuthClient(ctx, *existing)
		if err != nil {
			t.Fatalf("UpdateOAuthClient: %v", err)
		}
		if updated.ClientName != "Updated Name" {
			t.Fatalf("ClientName not updated: got %q", updated.ClientName)
		}
	})

	t.Run("GetMissing", func(t *testing.T) {
		if _, err := store.OAuthClientByClientID(ctx, "no-such-client"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if err := store.DeleteOAuthClient(ctx, clientID); err != nil {
			t.Fatalf("DeleteOAuthClient: %v", err)
		}
		if _, err := store.OAuthClientByClientID(ctx, clientID); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("after delete: want ErrNotFound, got %v", err)
		}
	})
}
