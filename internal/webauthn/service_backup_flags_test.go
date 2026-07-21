package webauthn_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/internal/ulid"
)

// This file is the regression suite for the synced-passkey login failure:
// go-webauthn's login validation rejects an assertion whose backup-eligible
// (BE) flag differs from the stored credential, and the library used to never
// persist BE/BS, so every synced passkey (BE=1) failed to log in. These tests
// drive a full register + login ceremony against a real ES256 virtual
// authenticator (the shared wavt helper deliberately does not emit
// library-acceptable attestations), so they exercise the actual go-webauthn
// validateLogin path end to end. Before the fix, testSyncedPasskeyLoginSucceeds
// fails with a "validate assertion failed" error; after it, both pass.

// WebAuthn authenticator-data flag bits (see the WebAuthn L3 spec, §6.1).
const (
	flagUP byte = 0x01 // user present
	flagUV byte = 0x04 // user verified
	flagBE byte = 0x08 // backup eligible
	flagBS byte = 0x10 // backup state
	flagAT byte = 0x40 // attested credential data included
)

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// virtualAuthenticator is a minimal but spec-correct ES256 authenticator. It
// produces attestation objects (fmt "none") and assertions that the upstream
// go-webauthn library accepts end to end, which is exactly what the shared
// wavt helper does not do. It is scoped to this test file on purpose.
type virtualAuthenticator struct {
	aaguid    [16]byte
	credID    []byte
	priv      *ecdsa.PrivateKey
	signCount uint32
}

func newVirtualAuthenticator(t *testing.T) *virtualAuthenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("cred id: %v", err)
	}
	va := &virtualAuthenticator{credID: credID, priv: priv}
	if _, err := rand.Read(va.aaguid[:]); err != nil {
		t.Fatalf("aaguid: %v", err)
	}
	return va
}

// cosePublicKey returns the credential public key as a COSE_Key (ES256 / P-256)
// CBOR map, the exact shape go-webauthn parses out of the attested credential
// data and later uses to verify the assertion signature.
func (va *virtualAuthenticator) cosePublicKey(t *testing.T) []byte {
	t.Helper()
	x := va.priv.X.FillBytes(make([]byte, 32))
	y := va.priv.Y.FillBytes(make([]byte, 32))
	key := map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: x,  // x coordinate
		-3: y,  // y coordinate
	}
	b, err := cbor.Marshal(key)
	if err != nil {
		t.Fatalf("marshal cose key: %v", err)
	}
	return b
}

// authenticatorData builds the raw authenticator-data byte string:
// rpIDHash(32) || flags(1) || signCount(4) || [attested credential data].
func (va *virtualAuthenticator) authenticatorData(t *testing.T, flags byte, withAttestedCred bool) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(testRPID))
	var buf bytes.Buffer
	buf.Write(rpHash[:])
	buf.WriteByte(flags)
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], va.signCount)
	buf.Write(sc[:])
	if withAttestedCred {
		buf.Write(va.aaguid[:])
		var idLen [2]byte
		binary.BigEndian.PutUint16(idLen[:], uint16(len(va.credID)))
		buf.Write(idLen[:])
		buf.Write(va.credID)
		buf.Write(va.cosePublicKey(t))
	}
	return buf.Bytes()
}

func clientDataJSON(t *testing.T, typ, challenge string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   challenge,
		"origin":      testOrigin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal clientData: %v", err)
	}
	return b
}

// registrationBody returns the JSON body a browser would POST to
// navigator.credentials.create's finish endpoint, carrying the requested BE/BS
// flags.
func (va *virtualAuthenticator) registrationBody(t *testing.T, challenge string, backupEligible, backupState bool) []byte {
	t.Helper()
	flags := flagUP | flagUV | flagAT
	if backupEligible {
		flags |= flagBE
	}
	if backupState {
		flags |= flagBS
	}
	authData := va.authenticatorData(t, flags, true)
	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		t.Fatalf("marshal attestationObject: %v", err)
	}
	cdj := clientDataJSON(t, "webauthn.create", challenge)
	body, err := json.Marshal(map[string]any{
		"id":    b64url(va.credID),
		"rawId": b64url(va.credID),
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": b64url(attObj),
			"clientDataJSON":    b64url(cdj),
		},
	})
	if err != nil {
		t.Fatalf("marshal registration body: %v", err)
	}
	return body
}

// assertionBody returns the JSON body a browser would POST to
// navigator.credentials.get's finish endpoint, signed with the authenticator's
// private key and asserting the requested BE/BS flags. It bumps the sign count
// each call so the service's replay guard is satisfied across repeated logins.
func (va *virtualAuthenticator) assertionBody(t *testing.T, challenge string, userHandle []byte, backupEligible, backupState bool) []byte {
	t.Helper()
	va.signCount++
	flags := flagUP | flagUV
	if backupEligible {
		flags |= flagBE
	}
	if backupState {
		flags |= flagBS
	}
	authData := va.authenticatorData(t, flags, false)
	cdj := clientDataJSON(t, "webauthn.get", challenge)
	cdjHash := sha256.Sum256(cdj)
	signed := append(append([]byte{}, authData...), cdjHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, va.priv, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"id":    b64url(va.credID),
		"rawId": b64url(va.credID),
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": b64url(authData),
			"clientDataJSON":    b64url(cdj),
			"signature":         b64url(sig),
			"userHandle":        b64url(userHandle),
		},
	})
	if err != nil {
		t.Fatalf("marshal assertion body: %v", err)
	}
	return body
}

// beginRegistrationChallenge starts a registration ceremony and returns the
// base64url challenge (as it appears in clientDataJSON) and the challenge token.
func beginRegistrationChallenge(t *testing.T, a *theauth.TheAuth, uid theauth.ULID) (string, string) {
	t.Helper()
	creation, tok, err := a.BeginPasskeyRegistration(context.Background(), uid)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}
	return b64url([]byte(creation.Response.Challenge)), tok
}

// beginLoginChallenge starts a discoverable-login ceremony and returns the
// base64url challenge and the challenge token.
func beginLoginChallenge(t *testing.T, a *theauth.TheAuth) (string, string) {
	t.Helper()
	assertion, tok, err := a.BeginPasskeyLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginPasskeyLogin: %v", err)
	}
	return b64url([]byte(assertion.Response.Challenge)), tok
}

// TestSyncedPasskeyBackupFlagLogin is the end-to-end regression suite. Both
// subtests run against the in-memory backend so they need no Postgres.
func TestSyncedPasskeyBackupFlagLogin(t *testing.T) {
	t.Run("registered_after_fix_synced_passkey_logs_in", testSyncedPasskeyLoginSucceeds)
	t.Run("legacy_credential_reconciles_on_first_login", testLegacyCredentialReconciles)
}

// testSyncedPasskeyLoginSucceeds registers a backup-eligible credential (a
// synced passkey) through the real ceremony and then logs in with an assertion
// that also reports BE=1. This is the exact production failure: before the fix
// the stored BE reads back false and go-webauthn rejects the login.
func testSyncedPasskeyLoginSucceeds(t *testing.T) {
	ctx := context.Background()
	a, store := newWebAuthnTestAuth(t)

	u, err := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "synced@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	va := newVirtualAuthenticator(t)

	regChallenge, regTok := beginRegistrationChallenge(t, a, u.ID)
	stored, err := a.FinishPasskeyRegistration(ctx, u.ID, regTok, "My Phone",
		bytes.NewReader(va.registrationBody(t, regChallenge, true, true)))
	if err != nil {
		t.Fatalf("FinishPasskeyRegistration: %v", err)
	}
	if stored.BackupEligible == nil || !*stored.BackupEligible {
		t.Fatalf("registration must persist BackupEligible=true, got %v", stored.BackupEligible)
	}
	if stored.BackupState == nil || !*stored.BackupState {
		t.Fatalf("registration must persist BackupState=true, got %v", stored.BackupState)
	}

	loginChallenge, loginTok := beginLoginChallenge(t, a)
	sessTok, _, err := a.FinishPasskeyLogin(ctx, loginTok,
		bytes.NewReader(va.assertionBody(t, loginChallenge, u.ID[:], true, true)),
		"ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("FinishPasskeyLogin for synced passkey must succeed, got: %v", err)
	}
	if sessTok == "" {
		t.Fatal("expected a non-empty session token on successful passkey login")
	}
}

// testLegacyCredentialReconciles inserts a credential row with NIL backup flags
// (a row written before the backup columns existed), confirms it logs in via
// the trust-on-first-use path, and confirms the reconciliation write stuck so
// the next login enforces the flag match normally.
func testLegacyCredentialReconciles(t *testing.T) {
	ctx := context.Background()
	a, store := newWebAuthnTestAuth(t)

	u, err := store.CreateUser(ctx, theauth.User{ID: ulid.New(), Email: "legacy@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	va := newVirtualAuthenticator(t)

	// Simulate a pre-fix row: valid COSE public key, but BackupEligible /
	// BackupState left nil (never recorded). Bypasses the registration path.
	legacy := theauth.WebAuthnCredential{
		ID:           ulid.New(),
		UserID:       u.ID,
		CredentialID: va.credID,
		PublicKey:    va.cosePublicKey(t),
		SignCount:    0,
		Transports:   []string{"internal"},
		AAGUID:       va.aaguid[:],
		Name:         "Legacy Key",
	}
	if _, err := store.InsertWebAuthnCredential(ctx, legacy); err != nil {
		t.Fatalf("InsertWebAuthnCredential (legacy): %v", err)
	}

	// First login: stored flags are nil, assertion reports BE=1. Without the
	// reconciliation path this fails go-webauthn's BE-equality check.
	loginChallenge, loginTok := beginLoginChallenge(t, a)
	if _, _, err := a.FinishPasskeyLogin(ctx, loginTok,
		bytes.NewReader(va.assertionBody(t, loginChallenge, u.ID[:], true, true)),
		"ua", "127.0.0.1"); err != nil {
		t.Fatalf("legacy first login must succeed via reconciliation, got: %v", err)
	}

	// The reconciliation write must have persisted the asserted flags.
	got, err := store.WebAuthnCredentialByCredentialID(ctx, va.credID)
	if err != nil {
		t.Fatalf("lookup after reconciliation: %v", err)
	}
	if got.BackupEligible == nil || !*got.BackupEligible {
		t.Fatalf("reconciliation must persist BackupEligible=true, got %v", got.BackupEligible)
	}
	if got.BackupState == nil || !*got.BackupState {
		t.Fatalf("reconciliation must persist BackupState=true, got %v", got.BackupState)
	}

	// Second login with the same (correct) flags now takes the strict path and
	// must still succeed, proving reconciliation did not break enforcement.
	loginChallenge2, loginTok2 := beginLoginChallenge(t, a)
	if _, _, err := a.FinishPasskeyLogin(ctx, loginTok2,
		bytes.NewReader(va.assertionBody(t, loginChallenge2, u.ID[:], true, true)),
		"ua", "127.0.0.1"); err != nil {
		t.Fatalf("legacy second login (strict path) must succeed, got: %v", err)
	}

	// A subsequent login that flips BE to 0 must now be rejected: the stored
	// flag is a real value and go-webauthn enforces equality. This confirms we
	// did not weaken security for the common case.
	loginChallenge3, loginTok3 := beginLoginChallenge(t, a)
	if _, _, err := a.FinishPasskeyLogin(ctx, loginTok3,
		bytes.NewReader(va.assertionBody(t, loginChallenge3, u.ID[:], false, false)),
		"ua", "127.0.0.1"); err == nil {
		t.Fatal("login with a mismatched (flipped) backup flag must be rejected after reconciliation")
	}
}
