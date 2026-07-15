package identitylink_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/identitylink"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
)

// flakyMoveStorage wraps memory.Store and injects a one-shot failure into
// any of the four Move* methods MergeAccounts calls in sequence.
type flakyMoveStorage struct {
	*memory.Store
	failOAuth, failPassword, failWebAuthn, failTOTP bool
}

func (s *flakyMoveStorage) MoveOAuthAccount(ctx context.Context, provider, providerUserID string, newUserID models.ULID) error {
	if s.failOAuth {
		s.failOAuth = false
		return errors.New("injected: oauth move failed")
	}
	return s.Store.MoveOAuthAccount(ctx, provider, providerUserID, newUserID)
}

func (s *flakyMoveStorage) MovePasswordHash(ctx context.Context, primaryID, secondaryID models.ULID) error {
	if s.failPassword {
		s.failPassword = false
		return errors.New("injected: password move failed")
	}
	return s.Store.MovePasswordHash(ctx, primaryID, secondaryID)
}

func (s *flakyMoveStorage) MoveWebAuthnCredentials(ctx context.Context, primaryID, secondaryID models.ULID) error {
	if s.failWebAuthn {
		s.failWebAuthn = false
		return errors.New("injected: webauthn move failed")
	}
	return s.Store.MoveWebAuthnCredentials(ctx, primaryID, secondaryID)
}

func (s *flakyMoveStorage) MoveTOTPSecret(ctx context.Context, primaryID, secondaryID models.ULID) error {
	if s.failTOTP {
		s.failTOTP = false
		return errors.New("injected: totp move failed")
	}
	return s.Store.MoveTOTPSecret(ctx, primaryID, secondaryID)
}

// mergeFixture seeds a primary user with a full session and a secondary
// user carrying one of every movable auth method.
type mergeFixture struct {
	store        *flakyMoveStorage
	primaryID    models.ULID
	secondaryID  models.ULID
	sessionToken string
}

func newMergeFixture(t *testing.T) *mergeFixture {
	t.Helper()
	ctx := context.Background()
	inner := memory.New()
	store := &flakyMoveStorage{Store: inner}

	primaryID := ulid.New()
	secondaryID := ulid.New()
	now := time.Now()
	if _, err := store.CreateUser(ctx, models.User{ID: primaryID, Email: "primary@merge.test", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("create primary: %v", err)
	}
	if _, err := store.CreateUser(ctx, models.User{ID: secondaryID, Email: "secondary@merge.test", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("create secondary: %v", err)
	}

	token := "test-session-token-" + secondaryID.String()
	sess := models.Session{
		ID:        ulid.New(),
		UserID:    primaryID,
		TokenHash: crypto.HashToken(token),
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		AuthLevel: models.AuthLevelFull,
	}
	if _, err := store.CreateSessionWithAuthLevel(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	if _, err := store.UpsertOAuthAccount(ctx, models.OAuthAccount{
		ID: ulid.New(), UserID: secondaryID, Provider: "github", ProviderUserID: "gh-123",
	}); err != nil {
		t.Fatalf("seed oauth account: %v", err)
	}
	if err := store.SetUserPassword(ctx, secondaryID, "argon2id$fake-hash"); err != nil {
		t.Fatalf("seed password: %v", err)
	}
	if _, err := store.InsertWebAuthnCredential(ctx, models.WebAuthnCredential{
		ID: ulid.New(), UserID: secondaryID, CredentialID: []byte("cred-" + secondaryID.String()), PublicKey: []byte("pk"), CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed webauthn credential: %v", err)
	}
	if err := store.UpsertPendingTOTPSecret(ctx, models.TOTPSecret{UserID: secondaryID, SecretEnc: []byte("totp-secret")}); err != nil {
		t.Fatalf("seed totp secret: %v", err)
	}

	return &mergeFixture{store: store, primaryID: primaryID, secondaryID: secondaryID, sessionToken: token}
}

// assertFullyMerged confirms every auth method moved to primaryID.
func (f *mergeFixture) assertFullyMerged(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	oauths, err := f.store.OAuthAccountsByUserID(ctx, f.primaryID)
	if err != nil || len(oauths) != 1 {
		t.Fatalf("primary should have 1 oauth account, got %d (err=%v)", len(oauths), err)
	}
	secOauths, _ := f.store.OAuthAccountsByUserID(ctx, f.secondaryID)
	if len(secOauths) != 0 {
		t.Fatalf("secondary should have 0 oauth accounts left, got %d", len(secOauths))
	}

	hash, err := f.store.UserPasswordHashByID(ctx, f.primaryID)
	if err != nil || hash == "" {
		t.Fatalf("primary should have the moved password hash, err=%v", err)
	}

	creds, err := f.store.WebAuthnCredentialsByUserID(ctx, f.primaryID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("primary should have 1 webauthn credential, got %d (err=%v)", len(creds), err)
	}

	secret, err := f.store.TOTPSecretByUserID(ctx, f.primaryID)
	if err != nil || secret == nil {
		t.Fatalf("primary should have the moved totp secret, err=%v", err)
	}
}

// TestMergeAccountsRetriesToCompletionAfterEachStepFails proves a failure
// at any of the four Move* steps is safe to retry to completion.
func TestMergeAccountsRetriesToCompletionAfterEachStepFails(t *testing.T) {
	cases := []struct {
		name   string
		inject func(*flakyMoveStorage)
	}{
		{"oauth step fails", func(s *flakyMoveStorage) { s.failOAuth = true }},
		{"password step fails", func(s *flakyMoveStorage) { s.failPassword = true }},
		{"webauthn step fails", func(s *flakyMoveStorage) { s.failWebAuthn = true }},
		{"totp step fails", func(s *flakyMoveStorage) { s.failTOTP = true }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newMergeFixture(t)
			svc := identitylink.New(fx.store, make([]byte, 32), nil)
			tc.inject(fx.store)

			if err := svc.MergeAccounts(context.Background(), fx.sessionToken, fx.secondaryID, identitylink.MergeInput{}); err == nil {
				t.Fatal("expected the injected failure to surface as an error")
			}

			// Retry with the same IDs: whatever already moved stays moved,
			// whatever didn't gets picked up now that the fault is gone.
			if err := svc.MergeAccounts(context.Background(), fx.sessionToken, fx.secondaryID, identitylink.MergeInput{}); err != nil {
				t.Fatalf("retry after %s should succeed, got: %v", tc.name, err)
			}
			fx.assertFullyMerged(t)
		})
	}
}
