package storagetest

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// RunLegacyTokenImport checks ImportAPIToken and AcceptUnprefixed end to end on a store.
func RunLegacyTokenImport(t *testing.T, store theauth.CoreStorage) {
	t.Helper()
	ctx := context.Background()
	newAuth := func(accept bool) *theauth.TheAuth {
		a, err := theauth.New(theauth.Config{
			CoreStorage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
			APITokens: &theauth.APITokensConfig{
				Prefix: "tk", AcceptUnprefixed: accept,
				UserAbilities: func(context.Context, *theauth.User) ([]string, error) { return []string{"read"}, nil },
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(a.Close)
		return a
	}
	off, on := newAuth(false), newAuth(true)
	u, err := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "import@h.com", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	hash := func(raw string) []byte { h := sha256.Sum256([]byte(raw)); return h[:] }
	imp := func(raw string, exp *time.Time) theauth.APIToken {
		tok, err := on.ImportAPIToken(ctx, theauth.ImportedToken{
			OwnerID: u.ID, Name: "legacy " + raw, Abilities: []string{"read"}, TokenHash: hash(raw),
			CreatedAt: past.Add(-time.Hour), ExpiresAt: exp,
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	imp("legacyrawtoken1", &future)
	imp("legacyrawtoken2", nil)
	imp("legacyexpired", &past)
	revoked := imp("legacyrevoked", &future)
	imp("tk_importedprefixed", &future)
	if err := on.RevokeAPIToken(ctx, revoked.ID); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		a    *theauth.TheAuth
		raw  string
		ok   bool
	}{
		{"unprefixed, flag on", on, "legacyrawtoken1", true},
		{"unprefixed no expiry, flag on", on, "legacyrawtoken2", true},
		{"unprefixed, flag off", off, "legacyrawtoken1", false},
		{"expired unprefixed", on, "legacyexpired", false},
		{"revoked unprefixed", on, "legacyrevoked", false},
		{"unknown unprefixed", on, "nosuchtoken", false},
		{"empty", on, "", false},
		{"imported prefixed, flag off", off, "tk_importedprefixed", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.a.AuthenticateAPIToken(ctx, tc.raw)
			if tc.ok {
				if err != nil || p.UserID != u.ID || p.TokenID == nil {
					t.Fatalf("want principal for owner, got %v %v", p, err)
				}
				return
			}
			if !errors.Is(err, theauth.ErrAPITokenInvalid) {
				t.Fatalf("want ErrAPITokenInvalid, got %v", err)
			}
		})
	}

	bad := []theauth.ImportedToken{
		{OwnerID: u.ID, Name: "x", TokenHash: []byte("short"), Abilities: []string{"read"}},
		{OwnerID: u.ID, Name: "x", TokenHash: hash("a"), Abilities: []string{"Bad Ability"}},
		{OwnerID: u.ID, Name: "", TokenHash: hash("b"), Abilities: []string{"read"}},
	}
	for i, in := range bad {
		if _, err := on.ImportAPIToken(ctx, in); err == nil {
			t.Fatalf("bad import %d accepted", i)
		}
	}
}
