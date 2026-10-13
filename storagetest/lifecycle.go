package storagetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage"
)

// LifecycleSuiteStorage is the storage RunAccountLifecycle needs.
type LifecycleSuiteStorage interface {
	theauth.UserStorage
	theauth.SessionStorage
	theauth.PasswordStorage
	theauth.OAuthAccountStorage
	theauth.WebAuthnStorage
	theauth.TOTPStorage
	theauth.APITokenStorage
	theauth.AccountStateStorage
	theauth.AccountDeleteStorage
	theauth.TrustedDeviceStorage
}

// RunAccountLifecycle runs the account state, cascade delete and trusted
// device contract tests.
func RunAccountLifecycle(t *testing.T, store LifecycleSuiteStorage) {
	t.Helper()
	t.Run("AccountState", func(t *testing.T) { testAccountState(t, store) })
	t.Run("TrustedDevices", func(t *testing.T) { testTrustedDevices(t, store) })
	t.Run("DeleteUserCascade", func(t *testing.T) { testDeleteUserCascade(t, store) })
}

func testAccountState(t *testing.T, store LifecycleSuiteStorage) {
	ctx := context.Background()
	uid := mkUser(t, store, "state-owner@storagetest.example")
	other := mkUser(t, store, "state-other@storagetest.example")

	st, err := store.AccountStateByUserID(ctx, uid)
	if err != nil || st.MustChangePassword || st.DisabledAt != nil {
		t.Fatalf("fresh state = %+v, %v; want zero", st, err)
	}
	if err := store.SetMustChangePassword(ctx, uid, true); err != nil {
		t.Fatalf("SetMustChangePassword: %v", err)
	}
	at := time.Now().Truncate(time.Millisecond)
	if err := store.SetUserDisabledAt(ctx, uid, &at); err != nil {
		t.Fatalf("SetUserDisabledAt: %v", err)
	}
	st, err = store.AccountStateByUserID(ctx, uid)
	if err != nil || !st.MustChangePassword || st.DisabledAt == nil || !st.DisabledAt.Equal(at) {
		t.Fatalf("state = %+v, %v; want both flags set", st, err)
	}
	if err := store.SetMustChangePassword(ctx, uid, false); err != nil {
		t.Fatal(err)
	}
	st, _ = store.AccountStateByUserID(ctx, uid)
	if st.MustChangePassword || st.DisabledAt == nil {
		t.Fatalf("clearing one flag must keep the other, got %+v", st)
	}
	if err := store.SetUserDisabledAt(ctx, uid, nil); err != nil {
		t.Fatal(err)
	}
	st, _ = store.AccountStateByUserID(ctx, uid)
	if st.DisabledAt != nil {
		t.Fatalf("re-enable must clear DisabledAt, got %+v", st)
	}
	if o, _ := store.AccountStateByUserID(ctx, other); o.MustChangePassword || o.DisabledAt != nil {
		t.Fatalf("other user touched: %+v", o)
	}
	if err := store.SetMustChangePassword(ctx, newID(), true); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unknown user: err = %v, want ErrNotFound", err)
	}
	if err := store.SetUserDisabledAt(ctx, newID(), &at); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unknown user disable: err = %v, want ErrNotFound", err)
	}
}

func mkDevice(user theauth.ULID, tag string, ttl time.Duration) theauth.TrustedDevice {
	now := time.Now().Truncate(time.Millisecond)
	return theauth.TrustedDevice{
		ID: newID(), UserID: user, TokenHash: sha256Hash([]byte(tag)), Label: "Chrome on macOS",
		UserAgent: "ua", IP: "203.0.113.7", CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(ttl),
	}
}

func testTrustedDevices(t *testing.T, store LifecycleSuiteStorage) {
	ctx := context.Background()
	owner := mkUser(t, store, "td-owner@storagetest.example")
	other := mkUser(t, store, "td-other@storagetest.example")

	a := mkDevice(owner, "td-a", time.Hour)
	b := mkDevice(owner, "td-b", time.Hour)
	b.CreatedAt = a.CreatedAt.Add(time.Second)
	expired := mkDevice(owner, "td-expired", -time.Minute)
	foreign := mkDevice(other, "td-foreign", time.Hour)
	for _, d := range []theauth.TrustedDevice{a, b, expired, foreign} {
		if err := store.InsertTrustedDevice(ctx, d); err != nil {
			t.Fatalf("InsertTrustedDevice: %v", err)
		}
	}

	got, err := store.TrustedDeviceByTokenHash(ctx, owner, a.TokenHash)
	if err != nil || got.ID != a.ID || got.Label != a.Label || got.RevokedAt != nil {
		t.Fatalf("ByTokenHash = %+v, %v", got, err)
	}
	if _, err := store.TrustedDeviceByTokenHash(ctx, other, a.TokenHash); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("cross-user lookup: err = %v, want ErrNotFound", err)
	}
	list, err := store.ListTrustedDevices(ctx, owner)
	if err != nil || len(list) != 2 || list[0].ID != b.ID || list[1].ID != a.ID {
		t.Fatalf("List = %+v, %v; want [b a] newest first without expired", list, err)
	}
	touch := time.Now().Add(time.Minute).Truncate(time.Millisecond)
	if err := store.TouchTrustedDevice(ctx, a.ID, touch); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if got, _ := store.TrustedDeviceByTokenHash(ctx, owner, a.TokenHash); !got.LastUsedAt.Equal(touch) {
		t.Fatalf("LastUsedAt = %v, want %v", got.LastUsedAt, touch)
	}
	if err := store.RevokeTrustedDevice(ctx, other, a.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("cross-user revoke: err = %v, want ErrNotFound", err)
	}
	if err := store.RevokeTrustedDevice(ctx, owner, a.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got, _ := store.TrustedDeviceByTokenHash(ctx, owner, a.TokenHash); got == nil || got.RevokedAt == nil {
		t.Fatalf("revoked row must report RevokedAt, got %+v", got)
	}
	n, err := store.RevokeUserTrustedDevices(ctx, owner)
	if err != nil || n < 1 {
		t.Fatalf("RevokeUserTrustedDevices = %d, %v", n, err)
	}
	if list, _ := store.ListTrustedDevices(ctx, owner); len(list) != 0 {
		t.Fatalf("List after revoke-all = %+v", list)
	}
	if list, _ := store.ListTrustedDevices(ctx, other); len(list) != 1 {
		t.Fatalf("other user's device must survive, got %+v", list)
	}
}

func testDeleteUserCascade(t *testing.T, store LifecycleSuiteStorage) {
	ctx := context.Background()
	victim := mkUser(t, store, "cascade-victim@storagetest.example")
	bystander := mkUser(t, store, "cascade-bystander@storagetest.example")
	now := time.Now()

	seed := func(user theauth.ULID, tag string) (sessHash, tokHash, devHash []byte, provider string) {
		sess := mkSession(t, store, user, "cascade-sess-"+tag, now, time.Hour, "")
		if err := store.SetUserPassword(ctx, user, "phc-"+tag); err != nil {
			t.Fatalf("SetUserPassword: %v", err)
		}
		provider = "prov-" + tag
		if _, err := store.UpsertOAuthAccount(ctx, theauth.OAuthAccount{
			ID: newID(), UserID: user, Provider: provider, ProviderUserID: "pu-" + tag,
			AccessTokenEnc: []byte("a"), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("UpsertOAuthAccount: %v", err)
		}
		if _, err := store.InsertWebAuthnCredential(ctx, theauth.WebAuthnCredential{
			ID: newID(), UserID: user, CredentialID: []byte("cred-" + tag), PublicKey: []byte("pk"),
			AAGUID: make([]byte, 16), Name: "key", CreatedAt: now,
		}); err != nil {
			t.Fatalf("InsertWebAuthnCredential: %v", err)
		}
		if err := store.UpsertPendingTOTPSecret(ctx, theauth.TOTPSecret{UserID: user, SecretEnc: []byte("s"), CreatedAt: now}); err != nil {
			t.Fatalf("UpsertPendingTOTPSecret: %v", err)
		}
		if err := store.InsertRecoveryCodes(ctx, []theauth.RecoveryCode{
			{ID: newID(), UserID: user, CodeHash: []byte("h-" + tag), CreatedAt: now},
		}); err != nil {
			t.Fatalf("InsertRecoveryCodes: %v", err)
		}
		tok := newTestToken(user, theauth.OwnerKindUser, "cascade-tok-"+tag, now)
		if _, err := store.InsertAPIToken(ctx, tok); err != nil {
			t.Fatalf("InsertAPIToken: %v", err)
		}
		dev := mkDevice(user, "cascade-dev-"+tag, time.Hour)
		if err := store.InsertTrustedDevice(ctx, dev); err != nil {
			t.Fatalf("InsertTrustedDevice: %v", err)
		}
		if err := store.SetMustChangePassword(ctx, user, true); err != nil {
			t.Fatalf("SetMustChangePassword: %v", err)
		}
		return sess.TokenHash, tok.TokenHash, dev.TokenHash, provider
	}
	vSess, vTok, vDev, vProv := seed(victim, "victim")
	bSess, bTok, bDev, bProv := seed(bystander, "bystander")

	if err := store.DeleteUserCascade(ctx, victim); err != nil {
		t.Fatalf("DeleteUserCascade: %v", err)
	}
	if err := store.DeleteUserCascade(ctx, victim); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("second delete: err = %v, want ErrNotFound", err)
	}

	gone := []struct {
		name string
		err  error
	}{
		{"user", errOf(store.UserByID(ctx, victim))},
		{"session", errOf(store.SessionByTokenHash(ctx, vSess))},
		{"api token", errOf(store.APITokenByHash(ctx, vTok))},
		{"trusted device", errOf(store.TrustedDeviceByTokenHash(ctx, victim, vDev))},
		{"totp secret", errOf(store.TOTPSecretByUserID(ctx, victim))},
	}
	for _, g := range gone {
		if !errors.Is(g.err, storage.ErrNotFound) {
			t.Errorf("victim %s still present: err = %v", g.name, g.err)
		}
	}
	if accts, err := store.OAuthAccountsByUserID(ctx, victim); err != nil || len(accts) != 0 {
		t.Errorf("victim oauth accounts = %+v, %v", accts, err)
	}
	if _, err := store.OAuthAccountByProviderUserID(ctx, vProv, "pu-victim"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("victim oauth account lookup: err = %v", err)
	}
	if creds, err := store.WebAuthnCredentialsByUserID(ctx, victim); err != nil || len(creds) != 0 {
		t.Errorf("victim passkeys = %+v, %v", creds, err)
	}
	if h, err := store.UserPasswordHashByID(ctx, victim); err == nil && h != "" {
		t.Errorf("victim password hash survived: %q", h)
	}
	if st, _ := store.AccountStateByUserID(ctx, victim); st.MustChangePassword {
		t.Errorf("victim account state survived: %+v", st)
	}

	// The bystander is untouched.
	if _, err := store.UserByID(ctx, bystander); err != nil {
		t.Fatalf("bystander user: %v", err)
	}
	if _, err := store.SessionByTokenHash(ctx, bSess); err != nil {
		t.Errorf("bystander session: %v", err)
	}
	if _, err := store.APITokenByHash(ctx, bTok); err != nil {
		t.Errorf("bystander api token: %v", err)
	}
	if _, err := store.TrustedDeviceByTokenHash(ctx, bystander, bDev); err != nil {
		t.Errorf("bystander trusted device: %v", err)
	}
	if _, err := store.OAuthAccountByProviderUserID(ctx, bProv, "pu-bystander"); err != nil {
		t.Errorf("bystander oauth account: %v", err)
	}
	if st, _ := store.AccountStateByUserID(ctx, bystander); !st.MustChangePassword {
		t.Errorf("bystander account state lost")
	}
}

// errOf returns the error of a two-value lookup.
func errOf[T any](_ T, err error) error { return err }
