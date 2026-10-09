package webauthn_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const (
	aaguidA = "11111111-2222-3333-4444-555555555555"
	aaguidB = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

func parseAAGUID(t *testing.T, s string) [16]byte {
	t.Helper()
	var out [16]byte
	clean := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			clean = append(clean, s[i])
		}
	}
	for i := range out {
		var b byte
		for _, c := range clean[i*2 : i*2+2] {
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			default:
				b |= c - 'a' + 10
			}
		}
		out[i] = b
	}
	return out
}

func TestAAGUIDPolicy(t *testing.T) {
	tests := []struct {
		name    string
		cfg     theauth.WebAuthnConfig
		aaguid  string
		wantErr bool
	}{
		{"no policy accepts anything", theauth.WebAuthnConfig{}, aaguidA, false},
		{"allowlist accepts listed", theauth.WebAuthnConfig{AAGUIDAllowlist: []string{aaguidA}}, aaguidA, false},
		{"allowlist accepts undashed uppercase config", theauth.WebAuthnConfig{AAGUIDAllowlist: []string{"11111111222233334444555555555555"}}, aaguidA, false},
		{"allowlist rejects unlisted", theauth.WebAuthnConfig{AAGUIDAllowlist: []string{aaguidA}}, aaguidB, true},
		{"denylist rejects listed", theauth.WebAuthnConfig{AAGUIDDenylist: []string{aaguidB}}, aaguidB, true},
		{"denylist accepts others", theauth.WebAuthnConfig{AAGUIDDenylist: []string{aaguidB}}, aaguidA, false},
		{"denylist wins over allowlist", theauth.WebAuthnConfig{AAGUIDAllowlist: []string{aaguidA}, AAGUIDDenylist: []string{aaguidA}}, aaguidA, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, store, _ := newPolicyAuth(t, tc.cfg)
			u, _ := store.CreateUser(context.Background(), theauth.User{ID: ulid.New(), Email: "p@example.com"})
			va := newVirtualAuthenticator(t)
			va.aaguid = parseAAGUID(t, tc.aaguid)
			cred, err := register(t, a, u.ID, va)
			if tc.wantErr {
				if err == nil {
					t.Fatal("registration must be rejected")
				}
				if !errors.Is(err, errAAGUID(err)) {
					t.Fatalf("want AAGUID policy error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("register: %v", err)
			}
			if string(cred.AAGUID) != string(va.aaguid[:]) {
				t.Fatal("AAGUID not recorded on credential")
			}
		})
	}
}

// errAAGUID returns the wrapped policy error when err carries one, so the
// test asserts on the cause rather than on message text.
func errAAGUID(err error) error {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if e.Error() == "theauth: authenticator model is not permitted by the AAGUID policy" {
			return e
		}
	}
	return errors.New("none")
}

func TestAAGUIDPolicyInvalidConfig(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	for name, wa := range map[string]theauth.WebAuthnConfig{
		"bad allowlist":  {AAGUIDAllowlist: []string{"nope"}},
		"bad denylist":   {AAGUIDDenylist: []string{"1234"}},
		"bad names key":  {AuthenticatorNames: map[string]string{"x": "y"}},
		"bad preference": {AttestationPreference: "sometimes"},
	} {
		t.Run(name, func(t *testing.T) {
			wa.RPID, wa.RPOrigins = testRPID, []string{testOrigin}
			_, err := theauth.New(theauth.Config{Storage: memory.New(), BaseURL: "http://localhost", EncryptionKey: key, WebAuthn: &wa})
			if err == nil {
				t.Fatal("New must reject the config")
			}
		})
	}
}

func TestAttestationPreference(t *testing.T) {
	tests := []struct{ pref, want string }{
		{"", "none"}, {"none", "none"}, {"indirect", "indirect"}, {"direct", "direct"}, {"enterprise", "enterprise"},
	}
	for _, tc := range tests {
		t.Run("pref_"+tc.pref, func(t *testing.T) {
			a, store, _ := newPolicyAuth(t, theauth.WebAuthnConfig{AttestationPreference: tc.pref})
			u, _ := store.CreateUser(context.Background(), theauth.User{ID: ulid.New(), Email: "a@example.com"})
			creation, _, err := a.BeginPasskeyRegistration(context.Background(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(creation.Response.Attestation); got != tc.want {
				t.Fatalf("attestation = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRequireAttestationStatementRejectsNone(t *testing.T) {
	a, store, _ := newPolicyAuth(t, theauth.WebAuthnConfig{AttestationPreference: "direct", RequireAttestationStatement: true})
	u, _ := store.CreateUser(context.Background(), theauth.User{ID: ulid.New(), Email: "n@example.com"})
	if _, err := register(t, a, u.ID, newVirtualAuthenticator(t)); err == nil {
		t.Fatal("a none attestation must be rejected when a statement is required")
	}
}

func TestAuthenticatorName(t *testing.T) {
	a, _, _ := newPolicyAuth(t, theauth.WebAuthnConfig{
		AuthenticatorNames: map[string]string{"11111111222233334444555555555555": "Static Key"},
		AuthenticatorName: func(id string) string {
			if id == aaguidB {
				return "Lookup Key"
			}
			return ""
		},
	})
	a1, b1 := parseAAGUID(t, aaguidA), parseAAGUID(t, aaguidB)
	if got := a.PasskeyAuthenticatorName(a1[:]); got != "Static Key" {
		t.Fatalf("map name = %q", got)
	}
	if got := a.PasskeyAuthenticatorName(b1[:]); got != "Lookup Key" {
		t.Fatalf("hook name = %q", got)
	}
	if got := a.PasskeyAuthenticatorName(make([]byte, 16)); got != "" {
		t.Fatalf("unknown name = %q", got)
	}
}

// Regression for pocket-id#1767: the relying party ID is fixed by config, and
// the set of accepted origins (for example a Safari or cross-domain front end
// served from a different host) is exactly RPOrigins, never the request host.
func TestRPIDAndOriginValidation(t *testing.T) {
	tests := []struct {
		name      string
		origins   []string
		wantRegOK bool
	}{
		{"exact origin", []string{testOrigin}, true},
		{"extra related origin listed", []string{"https://app.example.org", testOrigin}, true},
		{"assertion origin not listed", []string{"https://app.example.org"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, 32)
			_, _ = rand.Read(key)
			store := memory.New()
			a, err := theauth.New(theauth.Config{
				Storage: store, BaseURL: "http://localhost", EncryptionKey: key,
				WebAuthn: &theauth.WebAuthnConfig{RPID: testRPID, RPOrigins: tc.origins},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(a.Close)
			u, _ := store.CreateUser(context.Background(), theauth.User{ID: ulid.New(), Email: "o@example.com"})
			creation, _, err := a.BeginPasskeyRegistration(context.Background(), u.ID)
			if err != nil {
				t.Fatal(err)
			}
			if creation.Response.RelyingParty.ID != testRPID {
				t.Fatalf("rp id = %q, want %q", creation.Response.RelyingParty.ID, testRPID)
			}
			_, err = register(t, a, u.ID, newVirtualAuthenticator(t))
			if (err == nil) != tc.wantRegOK {
				t.Fatalf("register err = %v, wantOK %v", err, tc.wantRegOK)
			}
		})
	}
}
