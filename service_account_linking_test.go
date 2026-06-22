package theauth_test

// service_account_linking_test.go covers the five v2.3 identity-linking
// scenarios specified in the implementation proposal.
//
// Tests use the in-process memory adapter and call service methods directly
// via the export_test.go helpers so no HTTP layer is involved, keeping
// runtime fast and avoiding flakiness from network timing.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/identitylink"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
	"github.com/glincker/theauth-go/storage/memory"
)

// newLinkingAuth builds a minimal *theauth.TheAuth + memory.Store suitable
// for identity-linking tests. No providers needed; the linking service works
// regardless of whether OAuth providers are configured.
func newLinkingAuth(t *testing.T) (*theauth.TheAuth, *memory.Store) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "http://localhost",
		EncryptionKey: key,
		SessionTTL:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, store
}

// createUser is a thin helper that inserts a user directly into the store
// and returns a fully-authenticated session token for that user.
func createUserWithSession(t *testing.T, a *theauth.TheAuth, store *memory.Store, email string) (*theauth.User, string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	u, err := store.CreateUser(ctx, theauth.User{
		ID:        ulid.New(),
		Email:     email,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := theauth.IssueSessionForTest(a, ctx, u, "test-ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return &u, token
}

// linkOAuth calls identitylink.Service.LinkOAuthToCurrentUser via the
// exported test accessor on *theauth.TheAuth.
func linkOAuth(t *testing.T, a *theauth.TheAuth, sessionToken, provider, providerUserID string) error {
	t.Helper()
	return theauth.LinkOAuthForTest(a, context.Background(), sessionToken, provider, providerUserID)
}

// TestLinkOAuthHappyPath: user with a password account links an OAuth
// provider. After linking, look up the oauth_accounts row and verify it
// points to the original user.
func TestLinkOAuthHappyPath(t *testing.T) {
	a, store := newLinkingAuth(t)
	ctx := context.Background()

	_, sessToken := createUserWithSession(t, a, store, "alice@example.com")

	// Link a fake "testprovider" identity.
	if err := linkOAuth(t, a, sessToken, "testprovider", "puid-alice"); err != nil {
		t.Fatalf("LinkOAuth: %v", err)
	}

	// Verify the oauth_accounts row is present and bound to Alice.
	acct, err := store.OAuthAccountByProviderUserID(ctx, "testprovider", "puid-alice")
	if err != nil {
		t.Fatalf("OAuthAccountByProviderUserID: %v", err)
	}

	// Resolve the session to confirm it is the same user.
	sess, user, err := theauth.ValidateSessionForTest(a, ctx, sessToken)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	_ = sess
	if acct.UserID != user.ID {
		t.Errorf("oauth account user_id %v != session user_id %v", acct.UserID, user.ID)
	}
}

// TestLinkOAuthIdempotent: linking the same provider a second time with the
// same (provider, providerUserID) and the same session is a no-op.
func TestLinkOAuthIdempotent(t *testing.T) {
	a, store := newLinkingAuth(t)
	_, sessToken := createUserWithSession(t, a, store, "bob@example.com")

	if err := linkOAuth(t, a, sessToken, "testprovider", "puid-bob"); err != nil {
		t.Fatalf("first link: %v", err)
	}
	if err := linkOAuth(t, a, sessToken, "testprovider", "puid-bob"); err != nil {
		t.Fatalf("second link (idempotent): %v", err)
	}
}

// TestLinkOAuthConflictReturnsErrIdentityConflict: userA links GitHub.
// userB tries to link the same GitHub account. Expect an
// *IdentityConflictError wrapping ErrIdentityConflict with userA's ID.
func TestLinkOAuthConflictReturnsErrIdentityConflict(t *testing.T) {
	a, store := newLinkingAuth(t)

	userA, sessA := createUserWithSession(t, a, store, "userA@example.com")
	_, sessB := createUserWithSession(t, a, store, "userB@example.com")

	// userA claims the provider account.
	if err := linkOAuth(t, a, sessA, "testprovider", "shared-puid"); err != nil {
		t.Fatalf("userA link: %v", err)
	}

	// userB tries to claim the same provider account.
	err := linkOAuth(t, a, sessB, "testprovider", "shared-puid")
	if err == nil {
		t.Fatal("expected ErrIdentityConflict, got nil")
	}

	if !errors.Is(err, theauth.ErrIdentityConflict) {
		t.Fatalf("expected errors.Is ErrIdentityConflict; got %v", err)
	}

	var conflict *theauth.IdentityConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected *IdentityConflictError; got %T", err)
	}
	if conflict.ConflictingUserID != userA.ID {
		t.Errorf("ConflictingUserID = %v; want %v", conflict.ConflictingUserID, userA.ID)
	}
}

// TestMergeAccountsMovesAllIdentities: userA has a password, userB has a
// linked OAuth provider + TOTP secret. Merge B into A. Verify:
//   - A's store now has the OAuth row from B.
//   - A's TOTP secret came from B (A had none).
//   - B's session is revoked.
//   - A's session is still valid.
func TestMergeAccountsMovesAllIdentities(t *testing.T) {
	a, store := newLinkingAuth(t)
	ctx := context.Background()

	// Create userA with a password.
	userA, sessA := createUserWithSession(t, a, store, "userA-merge@example.com")
	if err := store.SetUserPassword(ctx, userA.ID, "$argon2id$v=19$placeholder"); err != nil {
		t.Fatal(err)
	}

	// Create userB and link an OAuth provider to B.
	userB, sessB := createUserWithSession(t, a, store, "userB-merge@example.com")
	if err := linkOAuth(t, a, sessB, "github", "gh-userB"); err != nil {
		t.Fatal(err)
	}

	// Give userB a confirmed TOTP secret.
	now := time.Now()
	if err := store.UpsertPendingTOTPSecret(ctx, theauth.TOTPSecret{
		UserID:    userB.ID,
		SecretEnc: []byte("encrypted-secret"),
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmTOTPSecret(ctx, userB.ID, now); err != nil {
		t.Fatal(err)
	}

	// Merge B into A.
	if err := theauth.MergeAccountsForTest(a, ctx, sessA, userB.ID); err != nil {
		t.Fatalf("MergeAccounts: %v", err)
	}

	// A should now own B's OAuth account.
	acct, err := store.OAuthAccountByProviderUserID(ctx, "github", "gh-userB")
	if err != nil {
		t.Fatalf("oauth account lookup after merge: %v", err)
	}
	if acct.UserID != userA.ID {
		t.Errorf("oauth account user_id = %v; want %v", acct.UserID, userA.ID)
	}

	// A should now have a TOTP secret.
	totp, err := store.TOTPSecretByUserID(ctx, userA.ID)
	if err != nil {
		t.Fatalf("TOTPSecretByUserID after merge: %v", err)
	}
	if totp == nil || totp.ConfirmedAt == nil {
		t.Error("expected confirmed TOTP secret on primary after merge")
	}

	// B's session should be revoked (ValidateSession returns an error).
	_, _, err = theauth.ValidateSessionForTest(a, ctx, sessB)
	if err == nil {
		t.Error("expected B's session to be revoked after merge")
	}

	// A's session should still be valid.
	_, _, err = theauth.ValidateSessionForTest(a, ctx, sessA)
	if err != nil {
		t.Errorf("A's session should still be valid: %v", err)
	}
}

// TestUnlinkLastAuthMethodFails: user has only one OAuth provider linked.
// Unlinking it should return ErrLastAuthMethod.
func TestUnlinkLastAuthMethodFails(t *testing.T) {
	a, store := newLinkingAuth(t)

	_, sessToken := createUserWithSession(t, a, store, "solo@example.com")

	// Link a single provider.
	if err := linkOAuth(t, a, sessToken, "github", "gh-solo"); err != nil {
		t.Fatal(err)
	}

	// The user's only auth method is the OAuth account (no password, no
	// WebAuthn, no TOTP). Unlinking should fail.
	err := theauth.UnlinkOAuthForTest(a, context.Background(), sessToken, "github")
	if err == nil {
		t.Fatal("expected ErrLastAuthMethod, got nil")
	}
	if !errors.Is(err, theauth.ErrLastAuthMethod) {
		t.Fatalf("expected ErrLastAuthMethod; got %v", err)
	}
}

// TestUnlinkSucceedsWhenMultipleMethods: user has both a password and an
// OAuth provider. Unlinking the OAuth provider should succeed.
func TestUnlinkSucceedsWhenMultipleMethods(t *testing.T) {
	a, store := newLinkingAuth(t)
	ctx := context.Background()

	user, sessToken := createUserWithSession(t, a, store, "multi@example.com")

	// Give the user a password.
	if err := store.SetUserPassword(ctx, user.ID, "$argon2id$v=19$placeholder"); err != nil {
		t.Fatal(err)
	}

	// Link a provider.
	if err := linkOAuth(t, a, sessToken, "github", "gh-multi"); err != nil {
		t.Fatal(err)
	}

	// Now unlink. Should succeed because the password remains.
	if err := theauth.UnlinkOAuthForTest(a, ctx, sessToken, "github"); err != nil {
		t.Fatalf("UnlinkOAuth: %v", err)
	}
}

// TestLinkPasswordToCurrentUser: a user signed in via OAuth adds a password.
func TestLinkPasswordToCurrentUser(t *testing.T) {
	a, store := newLinkingAuth(t)
	ctx := context.Background()

	user, sessToken := createUserWithSession(t, a, store, "pw-link@example.com")

	if err := theauth.LinkPasswordForTest(a, ctx, sessToken, "correct-horse-battery-staple"); err != nil {
		t.Fatalf("LinkPassword: %v", err)
	}

	hash, err := store.UserPasswordHashByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" {
		t.Error("expected password hash to be set after LinkPassword")
	}
}

// TestLinkPasswordWeakPasswordRejected: passwords shorter than 12 characters
// must be rejected.
func TestLinkPasswordWeakPasswordRejected(t *testing.T) {
	a, store := newLinkingAuth(t)
	_, sessToken := createUserWithSession(t, a, store, "weak@example.com")

	err := theauth.LinkPasswordForTest(a, context.Background(), sessToken, "short")
	if err == nil {
		t.Fatal("expected weak password error, got nil")
	}
	var te *models.TheAuthError
	if !errors.As(err, &te) || te.Code != models.CodeWeakPassword {
		t.Fatalf("expected CodeWeakPassword; got %v", err)
	}
}

// TestLinkRequiresStepUp: calling LinkOAuth with a pending_2fa session must
// return ErrStepUpRequired.
func TestLinkRequiresStepUp(t *testing.T) {
	a, store := newLinkingAuth(t)
	ctx := context.Background()

	now := time.Now()
	u, err := store.CreateUser(ctx, theauth.User{
		ID:        ulid.New(),
		Email:     "stepup@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mint a pending_2fa session directly via the storage adapter.
	tok, err := theauth.NewRawTokenForTest()
	if err != nil {
		t.Fatal(err)
	}
	hash := theauth.HashTokenForTest(tok)
	sess := theauth.Session{
		ID:        ulid.New(),
		UserID:    u.ID,
		TokenHash: hash,
		AuthLevel: theauth.AuthLevelPending2FA,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if _, err := store.CreateSessionWithAuthLevel(ctx, sess); err != nil {
		t.Fatal(err)
	}

	err = linkOAuth(t, a, tok, "github", "gh-stepup")
	if err == nil {
		t.Fatal("expected ErrStepUpRequired, got nil")
	}
	if !errors.Is(err, theauth.ErrStepUpRequired) {
		t.Fatalf("expected ErrStepUpRequired; got %v", err)
	}
}

// TestMergeRequiresStepUp: MergeAccounts with a pending_2fa session must
// return ErrStepUpRequired.
func TestMergeRequiresStepUp(t *testing.T) {
	a, store := newLinkingAuth(t)
	ctx := context.Background()

	now := time.Now()
	u, err := store.CreateUser(ctx, theauth.User{
		ID:        ulid.New(),
		Email:     "merge-stepup@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}

	secondary, err := store.CreateUser(ctx, theauth.User{
		ID:        ulid.New(),
		Email:     "secondary-stepup@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}

	tok, err := theauth.NewRawTokenForTest()
	if err != nil {
		t.Fatal(err)
	}
	hash := theauth.HashTokenForTest(tok)
	sess := theauth.Session{
		ID:        ulid.New(),
		UserID:    u.ID,
		TokenHash: hash,
		AuthLevel: theauth.AuthLevelPending2FA,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if _, err := store.CreateSessionWithAuthLevel(ctx, sess); err != nil {
		t.Fatal(err)
	}

	err = theauth.MergeAccountsForTest(a, ctx, tok, secondary.ID)
	if err == nil {
		t.Fatal("expected ErrStepUpRequired, got nil")
	}
	if !errors.Is(err, theauth.ErrStepUpRequired) {
		t.Fatalf("expected ErrStepUpRequired; got %v", err)
	}
}

// Suppress unused import warning: identitylink is imported for MergeInput type.
var _ identitylink.MergeInput
