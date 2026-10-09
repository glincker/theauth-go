package keycloak_test

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/cmd/theauth-migrate/internal"
	"github.com/glincker/theauth-go/v2/cmd/theauth-migrate/keycloak"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

func credential(t *testing.T, password string, iterations int, algo string) (secret, cred string) {
	t.Helper()
	salt := []byte("keycloak-salt-16")
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 64)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := json.Marshal(map[string]string{
		"value": base64.StdEncoding.EncodeToString(key), "salt": base64.StdEncoding.EncodeToString(salt),
	})
	c, _ := json.Marshal(map[string]any{"hashIterations": iterations, "algorithm": algo})
	return string(s), string(c)
}

func realm(t *testing.T) string {
	secret, cred := credential(t, "correct-horse-battery-staple", 27500, "pbkdf2-sha256")
	oldSecret, oldCred := credential(t, "x", 1000, "argon2")
	users := []map[string]any{
		{"id": "kc-1", "username": "ann", "email": "Ann@Example.com", "emailVerified": true, "enabled": true,
			"firstName": "Ann", "lastName": "Lee", "createdTimestamp": 1700000000000,
			"credentials": []map[string]string{{"type": "password", "secretData": secret, "credentialData": cred}, {"type": "otp"}}},
		{"id": "kc-2", "username": "bob", "email": "bob@example.com", "enabled": true,
			"credentials": []map[string]string{{"type": "password", "secretData": oldSecret, "credentialData": oldCred}}},
		{"id": "kc-3", "username": "carol", "email": "carol@example.com", "enabled": true,
			"federatedIdentities": []map[string]string{{"identityProvider": "google", "userId": "g-1"}}},
		{"id": "kc-4", "username": "dan", "email": "dan@example.com", "enabled": false},
		{"id": "kc-5", "username": "noemail"},
	}
	out, _ := json.Marshal(map[string]any{"realm": "demo", "users": users})
	return string(out)
}

func TestReadJSON(t *testing.T) {
	b, err := keycloak.ReadJSON(strings.NewReader(realm(t)), false)
	if err != nil {
		t.Fatal(err)
	}
	if b.Source != "keycloak" || len(b.Users) != 3 {
		t.Fatalf("source=%q users=%d, want keycloak and 3 (disabled and email-less skipped)", b.Source, len(b.Users))
	}
	byID := map[string]internal.UserRecord{}
	for _, u := range b.Users {
		byID[u.SourceID] = u
	}
	if byID["kc-1"].Email != "ann@example.com" || byID["kc-1"].Name != "Ann Lee" || !byID["kc-1"].RequiresMFAReenroll || byID["kc-1"].RequiresPasswordReset {
		t.Errorf("ann = %+v", byID["kc-1"])
	}
	if !byID["kc-2"].RequiresPasswordReset {
		t.Errorf("unsupported algorithm must force a reset: %+v", byID["kc-2"])
	}
	if byID["kc-3"].RequiresPasswordReset {
		t.Errorf("a federated-only user must not be forced to reset: %+v", byID["kc-3"])
	}
	if len(b.Passwords) != 1 || !strings.HasPrefix(b.Passwords[0].Hash, "$pbkdf2-sha256$27500$") || b.Passwords[0].Algo != "pbkdf2-sha256" {
		t.Errorf("passwords = %+v", b.Passwords)
	}
	if len(b.OAuthAccounts) != 1 || b.OAuthAccounts[0].Provider != "google" {
		t.Errorf("oauth = %+v", b.OAuthAccounts)
	}

	forced, _ := keycloak.ReadJSON(strings.NewReader(realm(t)), true)
	if len(forced.Passwords) != 0 || !forced.Users[0].RequiresPasswordReset {
		t.Errorf("force-password-reset must drop hashes: %+v", forced.Passwords)
	}
}

func signin(t *testing.T, h http.Handler, email, password string) int {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	req := httptest.NewRequest(http.MethodPost, "/auth/email-password/signin", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func router(t *testing.T, st *memory.Store, allowLegacy bool) http.Handler {
	t.Helper()
	a, err := theauth.New(theauth.Config{
		Storage: st, BaseURL: "http://localhost", RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
		PasswordPolicy: theauth.PasswordPolicyConfig{AllowLegacyBcrypt: allowLegacy},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	r := chi.NewRouter()
	a.Mount(r)
	return r
}

// A migrated Keycloak user signs in with the old password, and after that one
// login the hash is Argon2id: it keeps working with legacy support off.
func TestKeycloakMigrationSignInAndRehash(t *testing.T) {
	bundle, err := keycloak.ReadJSON(strings.NewReader(realm(t)), false)
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	if _, err := internal.ApplyBundle(context.Background(), st, bundle, internal.ApplyOptions{Out: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}

	if got := signin(t, router(t, st, false), "ann@example.com", "correct-horse-battery-staple"); got == http.StatusOK {
		t.Fatal("legacy hash must not be accepted while AllowLegacyBcrypt is off")
	}
	legacy := router(t, st, true)
	if got := signin(t, legacy, "ann@example.com", "wrong-password"); got == http.StatusOK {
		t.Fatal("wrong password accepted")
	}
	if got := signin(t, legacy, "ann@example.com", "correct-horse-battery-staple"); got != http.StatusOK {
		t.Fatalf("migrated user sign-in = %d, want 200", got)
	}
	if got := signin(t, router(t, st, false), "ann@example.com", "correct-horse-battery-staple"); got != http.StatusOK {
		t.Fatalf("after the first login the hash must be Argon2id; sign-in with legacy off = %d", got)
	}
}
