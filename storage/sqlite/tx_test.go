package sqlite_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 default HMAC for authenticator apps, not a security primitive here
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
)

const totpSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

func totpCode(secret string, at time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(at.Unix()/30))
	m := hmac.New(sha1.New, key)
	m.Write(buf[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

func libraryTables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'theauth\_%' ESCAPE '\' AND name NOT LIKE '%schema_migrations'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		t.Fatal("no library tables found")
	}
	return out
}

func rowCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func singleConnDB(t *testing.T) *sql.DB {
	t.Helper()
	db := openDB(t)
	if err := sqlitestore.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	return db
}

func runBackfill(t *testing.T, ctx context.Context, tx *sql.Tx, key []byte) theauth.User {
	t.Helper()
	st, err := sqlitestore.NewTx(tx)
	if err != nil {
		t.Fatalf("NewTx: %v", err)
	}
	u, err := theauth.ImportUserTo(ctx, st, theauth.ImportedUser{
		Email: "legacy@example.com", Name: "Legacy", PasswordHash: "$2a$04$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
		CreatedAt: time.Now().Add(-48 * time.Hour),
	})
	if err != nil {
		t.Fatalf("ImportUserTo: %v", err)
	}
	h := sha256.Sum256([]byte("rawlegacytoken"))
	if _, err := theauth.ImportAPITokenTo(ctx, st, theauth.ImportedToken{
		OwnerID: u.ID, Name: "legacy token", Abilities: []string{"read"}, TokenHash: h[:],
	}); err != nil {
		t.Fatalf("ImportAPITokenTo: %v", err)
	}
	if err := theauth.ImportTOTPSecretTo(ctx, st, key, theauth.ImportedTOTP{UserID: u.ID, Secret: strings.ToLower(totpSecret)}); err != nil {
		t.Fatalf("ImportTOTPSecretTo: %v", err)
	}
	if _, err := theauth.ImportWebAuthnCredentialTo(ctx, st, theauth.ImportedWebAuthnCredential{
		UserID: u.ID, CredentialID: []byte("cred-1"), PublicKey: []byte("pub"), SignCount: 7,
		Transports: []string{"internal"}, AAGUID: make([]byte, 16), Name: "phone",
	}); err != nil {
		t.Fatalf("ImportWebAuthnCredentialTo: %v", err)
	}

	if _, err := theauth.ImportUserTo(ctx, st, theauth.ImportedUser{Email: "LEGACY@example.com"}); !errors.Is(err, theauth.ErrImportDuplicate) {
		t.Fatalf("duplicate user: %v", err)
	}
	if _, err := theauth.ImportAPITokenTo(ctx, st, theauth.ImportedToken{
		OwnerID: u.ID, Name: "again", Abilities: []string{"read"}, TokenHash: h[:],
	}); !errors.Is(err, theauth.ErrImportDuplicate) {
		t.Fatalf("duplicate token: %v", err)
	}
	if err := theauth.ImportTOTPSecretTo(ctx, st, key, theauth.ImportedTOTP{UserID: u.ID, Secret: totpSecret}); !errors.Is(err, theauth.ErrImportDuplicate) {
		t.Fatalf("duplicate totp: %v", err)
	}
	if _, err := theauth.ImportWebAuthnCredentialTo(ctx, st, theauth.ImportedWebAuthnCredential{
		UserID: u.ID, CredentialID: []byte("cred-1"), PublicKey: []byte("pub"),
	}); !errors.Is(err, theauth.ErrImportDuplicate) {
		t.Fatalf("duplicate credential: %v", err)
	}
	return u
}

func TestNewTxImportRollbackAndCommit(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	for _, commit := range []bool{false, true} {
		name := "rollback"
		if commit {
			name = "commit"
		}
		t.Run(name, func(t *testing.T) {
			db := singleConnDB(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			u := runBackfill(t, ctx, tx, key)
			if commit {
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
			} else if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}

			if !commit {
				for _, tbl := range libraryTables(t, db) {
					if n := rowCount(t, db, tbl); n != 0 {
						t.Errorf("%s has %d rows after rollback", tbl, n)
					}
				}
				return
			}
			for _, tbl := range []string{"theauth_users", "theauth_user_passwords", "theauth_api_tokens", "theauth_totp_secrets", "theauth_webauthn_credentials"} {
				if rowCount(t, db, tbl) != 1 {
					t.Errorf("%s: want 1 row after commit", tbl)
				}
			}
			verifyImportedTOTP(t, ctx, db, key, u)
		})
	}
}

func verifyImportedTOTP(t *testing.T, ctx context.Context, db *sql.DB, key []byte, u theauth.User) {
	t.Helper()
	store, err := sqlitestore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		CoreStorage: store, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		EncryptionKey: key, TOTP: &theauth.TOTPConfig{Issuer: "test"},
		SuppressSecureCookieWarning: true, SuppressTrustedProxiesWarning: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	pending := func(tok string) {
		t.Helper()
		now := time.Now()
		if _, err := store.CreateSessionWithAuthLevel(ctx, theauth.Session{
			ID: newID(), UserID: u.ID, TokenHash: crypto.HashToken(tok), CreatedAt: now,
			ExpiresAt: now.Add(time.Minute), AuthLevel: theauth.AuthLevelPending2FA,
		}); err != nil {
			t.Fatal(err)
		}
	}
	pending("pend-bad")
	if _, _, err := a.VerifyTOTP(ctx, "pend-bad", "000000"); err == nil {
		t.Fatal("wrong code accepted")
	}
	pending("pend-good")
	if _, _, err := a.VerifyTOTP(ctx, "pend-good", totpCode(totpSecret, time.Now())); err != nil {
		t.Fatalf("imported secret rejected a valid code: %v", err)
	}
}

func TestNewTxNoDeadlockOnSingleConnection(t *testing.T) {
	db := singleConnDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	st, err := sqlitestore.NewTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		u, err := st.CreateUser(ctx, theauth.User{ID: newID(), Email: "a@b.co", CreatedAt: time.Now()})
		if err == nil {
			err = st.InsertRecoveryCodes(ctx, []theauth.RecoveryCode{{ID: newID(), UserID: u.ID, CodeHash: []byte("h"), CreatedAt: time.Now()}})
		}
		if err == nil {
			_, err = st.SweepExpired(ctx, time.Now())
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("store bound to a transaction deadlocked on a single connection")
	}
}

func TestNewTxSavepointRollsBackFailedOperation(t *testing.T) {
	db := singleConnDB(t)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	st, err := sqlitestore.NewTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.CreateUser(ctx, theauth.User{ID: newID(), Email: "sp@b.co", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	dupID := newID()
	bad := []theauth.RecoveryCode{
		{ID: dupID, UserID: u.ID, CodeHash: []byte("1"), CreatedAt: time.Now()},
		{ID: dupID, UserID: u.ID, CodeHash: []byte("2"), CreatedAt: time.Now()},
	}
	if err := st.InsertRecoveryCodes(ctx, bad); err == nil {
		t.Fatal("duplicate recovery code ids accepted")
	}
	if n, err := st.CountUnusedRecoveryCodes(ctx, u.ID); err != nil || n != 0 {
		t.Fatalf("failed batch left %d rows (err %v)", n, err)
	}
	if _, err := st.UserByID(ctx, u.ID); err != nil {
		t.Fatalf("earlier work in the transaction was lost: %v", err)
	}
}

func TestNewTxRejectsNil(t *testing.T) {
	if _, err := sqlitestore.NewTx(nil); err == nil {
		t.Fatal("NewTx accepted a nil transaction")
	}
}
