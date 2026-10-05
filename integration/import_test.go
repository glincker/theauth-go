package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func TestImportHelpersValidateAndDedupe(t *testing.T) {
	ctx := context.Background()
	key := []byte("0123456789abcdef0123456789abcdef")
	a, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		EncryptionKey: key, TOTP: &theauth.TOTPConfig{Issuer: "t"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	u, err := a.ImportUser(ctx, theauth.ImportedUser{Email: "x@y.co", PasswordHash: "$2a$04$hash"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ImportUser(ctx, theauth.ImportedUser{Email: "x@y.co"}); !errors.Is(err, theauth.ErrImportDuplicate) {
		t.Fatalf("want duplicate, got %v", err)
	}
	if _, err := a.ImportUser(ctx, theauth.ImportedUser{Email: "nope"}); !errors.Is(err, theauth.ErrImportInvalid) {
		t.Fatalf("want invalid, got %v", err)
	}

	totpCases := []struct {
		name    string
		in      theauth.ImportedTOTP
		wantErr error
	}{
		{"not base32", theauth.ImportedTOTP{UserID: u.ID, Secret: "!!!"}, theauth.ErrImportInvalid},
		{"empty", theauth.ImportedTOTP{UserID: u.ID}, theauth.ErrImportInvalid},
		{"no user", theauth.ImportedTOTP{Secret: "JBSWY3DPEHPK3PXP"}, theauth.ErrImportInvalid},
		{"ok with spaces", theauth.ImportedTOTP{UserID: u.ID, Secret: "jbsw y3dp ehpk 3pxp"}, nil},
		{"duplicate", theauth.ImportedTOTP{UserID: u.ID, Secret: "JBSWY3DPEHPK3PXP"}, theauth.ErrImportDuplicate},
	}
	for _, tc := range totpCases {
		t.Run(tc.name, func(t *testing.T) {
			err := a.ImportTOTPSecret(ctx, tc.in)
			if !errors.Is(err, tc.wantErr) && (tc.wantErr != nil || err != nil) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
	if err := theauth.ImportTOTPSecretTo(ctx, memory.New(), []byte("short"), theauth.ImportedTOTP{UserID: u.ID, Secret: "JBSWY3DP"}); err == nil {
		t.Fatal("short encryption key accepted")
	}

	credCases := []struct {
		name    string
		in      theauth.ImportedWebAuthnCredential
		wantErr error
	}{
		{"no credential id", theauth.ImportedWebAuthnCredential{UserID: u.ID, PublicKey: []byte("k")}, theauth.ErrImportInvalid},
		{"no public key", theauth.ImportedWebAuthnCredential{UserID: u.ID, CredentialID: []byte("c")}, theauth.ErrImportInvalid},
		{"bad aaguid", theauth.ImportedWebAuthnCredential{UserID: u.ID, CredentialID: []byte("c"), PublicKey: []byte("k"), AAGUID: []byte{1}}, theauth.ErrImportInvalid},
		{"ok", theauth.ImportedWebAuthnCredential{UserID: u.ID, CredentialID: []byte("c"), PublicKey: []byte("k")}, nil},
		{"duplicate", theauth.ImportedWebAuthnCredential{UserID: u.ID, CredentialID: []byte("c"), PublicKey: []byte("k")}, theauth.ErrImportDuplicate},
	}
	for _, tc := range credCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.ImportWebAuthnCredential(ctx, tc.in)
			if !errors.Is(err, tc.wantErr) && (tc.wantErr != nil || err != nil) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}
