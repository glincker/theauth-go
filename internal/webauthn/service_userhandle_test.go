package webauthn_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

func importedFor(t *testing.T, a *theauth.TheAuth, uid theauth.ULID, va *virtualAuthenticator) {
	t.Helper()
	_, err := a.ImportWebAuthnCredential(context.Background(), theauth.ImportedWebAuthnCredential{
		UserID: uid, CredentialID: va.credID, PublicKey: va.cosePublicKey(t), AAGUID: va.aaguid[:], Name: "imported",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
}

func loginWithHandle(t *testing.T, a *theauth.TheAuth, va *virtualAuthenticator, handle []byte) error {
	t.Helper()
	chal, tok := beginLoginChallenge(t, a)
	_, _, err := a.FinishPasskeyLogin(context.Background(), tok, bytes.NewReader(va.assertionBody(t, chal, handle, false, false)), "ua", "198.51.100.9")
	return err
}

func TestImportedPasskeyForeignUserHandle(t *testing.T) {
	foreign := []byte("user_0123456789abcdef0123456789abcdef")
	tests := []struct {
		name     string
		resolver func(owner, other theauth.ULID) func(context.Context, []byte, []byte) (theauth.ULID, error)
		handle   []byte
		missing  bool
		wantErr  bool
	}{
		{"no resolver keeps default rejection", nil, foreign, false, true},
		{"resolver agreeing with owner signs in", func(owner, _ theauth.ULID) func(context.Context, []byte, []byte) (theauth.ULID, error) {
			return func(_ context.Context, _, h []byte) (theauth.ULID, error) {
				if !bytes.Equal(h, foreign) {
					return theauth.ULID{}, errors.New("unknown alias")
				}
				return owner, nil
			}
		}, foreign, false, false},
		{"handle resolving to another user is rejected", func(_, other theauth.ULID) func(context.Context, []byte, []byte) (theauth.ULID, error) {
			return func(context.Context, []byte, []byte) (theauth.ULID, error) { return other, nil }
		}, foreign, false, true},
		{"resolver error is rejected", func(_, _ theauth.ULID) func(context.Context, []byte, []byte) (theauth.ULID, error) {
			return func(context.Context, []byte, []byte) (theauth.ULID, error) { return theauth.ULID{}, errors.New("nope") }
		}, foreign, false, true},
		{"credential not in storage is rejected", func(owner, _ theauth.ULID) func(context.Context, []byte, []byte) (theauth.ULID, error) {
			return func(context.Context, []byte, []byte) (theauth.ULID, error) { return owner, nil }
		}, foreign, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			wa := theauth.WebAuthnConfig{}
			ownerID, otherID := ulid.New(), ulid.New()
			if tc.resolver != nil {
				wa.UserHandleResolver = tc.resolver(ownerID, otherID)
			}
			a, store, _ := newPolicyAuth(t, wa)
			_, _ = store.CreateUser(ctx, theauth.User{ID: ownerID, Email: "owner@example.com"})
			_, _ = store.CreateUser(ctx, theauth.User{ID: otherID, Email: "other@example.com"})
			va := newVirtualAuthenticator(t)
			if !tc.missing {
				importedFor(t, a, ownerID, va)
			}
			err := loginWithHandle(t, a, va, tc.handle)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestImportedPasskeyForeignHandleKeepsReplayProtection(t *testing.T) {
	ctx := context.Background()
	foreign := []byte("user_deadbeef")
	ownerID := ulid.New()
	a, store, _ := newPolicyAuth(t, theauth.WebAuthnConfig{
		UserHandleResolver: func(context.Context, []byte, []byte) (theauth.ULID, error) { return ownerID, nil },
	})
	if _, err := store.CreateUser(ctx, theauth.User{ID: ownerID, Email: "owner@example.com"}); err != nil {
		t.Fatal(err)
	}
	va := newVirtualAuthenticator(t)
	importedFor(t, a, ownerID, va)
	if err := loginWithHandle(t, a, va, foreign); err != nil {
		t.Fatalf("first login: %v", err)
	}
	va.freezeCount = true
	if err := loginWithHandle(t, a, va, foreign); !errors.Is(err, theauth.ErrReplayDetected) {
		t.Fatalf("sign count regression must be rejected, got %v", err)
	}
}

func TestLibraryHandleStillWorksWithResolverSet(t *testing.T) {
	ctx := context.Background()
	a, store, _ := newPolicyAuth(t, theauth.WebAuthnConfig{
		UserHandleResolver: func(context.Context, []byte, []byte) (theauth.ULID, error) {
			return theauth.ULID{}, errors.New("unused")
		},
	})
	u, _ := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "lib@example.com"})
	va := newVirtualAuthenticator(t)
	if _, err := register(t, a, u.ID, va); err != nil {
		t.Fatal(err)
	}
	if err := login(t, a, u.ID, va); err != nil {
		t.Fatalf("library handle login: %v", err)
	}
}
