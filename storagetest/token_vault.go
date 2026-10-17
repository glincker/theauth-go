package storagetest

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

// RunTokenVault runs the token vault credential contract tests.
func RunTokenVault(t *testing.T, store theauth.TokenVaultStorage) {
	t.Helper()
	t.Run("TokenVault", func(t *testing.T) { testTokenVault(t, store) })
}

func testTokenVault(t *testing.T, store theauth.TokenVaultStorage) {
	ctx := context.Background()
	user := newID().String()
	cred := func(provider string) theauth.VaultCredential {
		return theauth.VaultCredential{
			UserID: user, Provider: provider, AccountID: "acct", Scopes: []string{"a", "b"},
			AccessCT: []byte("access-ct"), RefreshCT: []byte("refresh-ct"),
			AccessExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
			Status:          theauth.VaultStatusActive,
		}
	}

	t.Run("missing is ErrNotFound", func(t *testing.T) {
		if _, err := store.VaultCredentialByUserProvider(ctx, user, "none"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
	t.Run("put get replace", func(t *testing.T) {
		got, err := store.PutVaultCredential(ctx, cred("p1"))
		if err != nil || got.ID == "" || got.Version != 1 {
			t.Fatalf("put = %+v, %v", got, err)
		}
		c := cred("p1")
		c.AccessCT = []byte("new")
		again, err := store.PutVaultCredential(ctx, c)
		if err != nil || again.ID != got.ID || again.Version != 2 {
			t.Fatalf("replace = %+v, %v", again, err)
		}
		read, err := store.VaultCredentialByUserProvider(ctx, user, "p1")
		if err != nil || !bytes.Equal(read.AccessCT, []byte("new")) || len(read.Scopes) != 2 {
			t.Fatalf("read = %+v, %v", read, err)
		}
	})
	t.Run("returned slices are copies", func(t *testing.T) {
		if _, err := store.PutVaultCredential(ctx, cred("p2")); err != nil {
			t.Fatal(err)
		}
		a, _ := store.VaultCredentialByUserProvider(ctx, user, "p2")
		a.AccessCT[0] = 'X'
		a.Scopes[0] = "mutated"
		b, _ := store.VaultCredentialByUserProvider(ctx, user, "p2")
		if b.AccessCT[0] == 'X' || b.Scopes[0] == "mutated" {
			t.Fatal("store aliases caller memory")
		}
	})
	t.Run("swap needs matching version", func(t *testing.T) {
		cur, _ := store.VaultCredentialByUserProvider(ctx, user, "p2")
		next := *cur
		next.AccessCT = []byte("swapped")
		if ok, err := store.SwapVaultCredential(ctx, next, cur.Version+5); err != nil || ok {
			t.Fatalf("stale swap = %v, %v", ok, err)
		}
		if ok, err := store.SwapVaultCredential(ctx, next, cur.Version); err != nil || !ok {
			t.Fatalf("swap = %v, %v", ok, err)
		}
		if ok, _ := store.SwapVaultCredential(ctx, next, cur.Version); ok {
			t.Fatal("second swap with the old version won")
		}
		read, _ := store.VaultCredentialByUserProvider(ctx, user, "p2")
		if read.Version != cur.Version+1 || !bytes.Equal(read.AccessCT, []byte("swapped")) {
			t.Fatalf("after swap = %+v", read)
		}
	})
	t.Run("swap missing row", func(t *testing.T) {
		c := cred("ghost")
		if ok, err := store.SwapVaultCredential(ctx, c, 1); err != nil || ok {
			t.Fatalf("swap missing = %v, %v", ok, err)
		}
	})
	t.Run("list is per user", func(t *testing.T) {
		other := cred("p1")
		other.UserID = newID().String()
		if _, err := store.PutVaultCredential(ctx, other); err != nil {
			t.Fatal(err)
		}
		list, err := store.ListVaultCredentials(ctx, user)
		if err != nil || len(list) != 2 {
			t.Fatalf("list = %d, %v", len(list), err)
		}
		for _, c := range list {
			if c.UserID != user {
				t.Fatal("list leaked another user's row")
			}
		}
	})
	t.Run("scan pages in id order", func(t *testing.T) {
		after, seen := "", 0
		for {
			page, err := store.ScanVaultCredentials(ctx, after, 2)
			if err != nil {
				t.Fatal(err)
			}
			if len(page) == 0 {
				break
			}
			for _, c := range page {
				if c.ID <= after {
					t.Fatalf("id %s not after %s", c.ID, after)
				}
				after = c.ID
				seen++
			}
		}
		if seen < 3 {
			t.Fatalf("scan saw %d rows, want at least 3", seen)
		}
	})
	t.Run("delete is idempotent", func(t *testing.T) {
		if err := store.DeleteVaultCredential(ctx, user, "p1"); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteVaultCredential(ctx, user, "p1"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.VaultCredentialByUserProvider(ctx, user, "p1"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("after delete err = %v", err)
		}
	})
}
