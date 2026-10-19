package attest

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// testdata/tpm2-swtpm.json holds data from a software TPM (swtpm 0.7.3 with tpm2-tools 5.7 and
// tpm2-pytss 2.3.0, made by docs-local/tpm2/gen.sh): real EK, AK and key public areas, a real
// TPM2_Certify output, and known answer MakeCredential blobs that TPM2_ActivateCredential accepted.

type tpmFixtureSide struct {
	EKPublic          string `json:"ekPublic"`
	AKPublic          string `json:"akPublic"`
	AKName            string `json:"akName"`
	KeyPublic         string `json:"keyPublic"`
	KeyName           string `json:"keyName"`
	QualifyingData    string `json:"qualifyingData"`
	CertifyInfo       string `json:"certifyInfo"`
	CertifySignature  string `json:"certifySignature"`
	TPMMakeCredential struct {
		Credential      string `json:"credential"`
		CredentialBlob  string `json:"credentialBlob"`
		EncryptedSecret string `json:"encryptedSecret"`
		Recovered       string `json:"recovered"`
	} `json:"tpmMakeCredential"`
}

type tpmFixture struct {
	RSA tpmFixtureSide `json:"rsa"`
	ECC tpmFixtureSide `json:"ecc"`
	KAT struct {
		RSA struct {
			Seed, Credential, CredentialBlob, EncryptedSecret, RecoveredByTPM string
		} `json:"rsa"`
		ECC struct {
			EphemeralPrivateJWK struct {
				D string `json:"d"`
			} `json:"ephemeralPrivateJwk"`
			Credential, CredentialBlob, EncryptedSecret, RecoveredByTPM string
		} `json:"ecc"`
	} `json:"makeCredentialKat"`
}

func loadTPMFixture(t *testing.T) tpmFixture {
	t.Helper()
	var f tpmFixture
	readJSON(t, "testdata/tpm2-swtpm.json", &f)
	return f
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := decodeBase64(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func b64s(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMakeCredentialRSAKnownAnswer(t *testing.T) {
	f := loadTPMFixture(t)
	made, err := MakeCredential(b64(t, f.RSA.EKPublic), mustHex(t, f.RSA.AKName), mustHex(t, f.KAT.RSA.Credential),
		&MakeCredentialRandomness{Seed: mustHex(t, f.KAT.RSA.Seed)})
	if err != nil {
		t.Fatal(err)
	}
	if b64s(made.CredentialBlob) != f.KAT.RSA.CredentialBlob {
		t.Fatalf("blob differs from the one the TPM accepted\n got %s\nwant %s", b64s(made.CredentialBlob), f.KAT.RSA.CredentialBlob)
	}
	if len(made.EncryptedSecret) != 2+256 || f.KAT.RSA.RecoveredByTPM != f.KAT.RSA.Credential {
		t.Fatalf("secret length %d, recovered %s", len(made.EncryptedSecret), f.KAT.RSA.RecoveredByTPM)
	}
}

func TestMakeCredentialECCKnownAnswer(t *testing.T) {
	f := loadTPMFixture(t)
	d, err := decodeBase64(f.KAT.ECC.EphemeralPrivateJWK.D)
	if err != nil {
		t.Fatal(err)
	}
	eph, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		t.Fatal(err)
	}
	made, err := MakeCredential(b64(t, f.ECC.EKPublic), mustHex(t, f.ECC.AKName), mustHex(t, f.KAT.ECC.Credential),
		&MakeCredentialRandomness{Ephemeral: eph})
	if err != nil {
		t.Fatal(err)
	}
	if b64s(made.CredentialBlob) != f.KAT.ECC.CredentialBlob || b64s(made.EncryptedSecret) != f.KAT.ECC.EncryptedSecret {
		t.Fatal("blob or encrypted secret differs from the ones the TPM accepted")
	}
	if f.KAT.ECC.RecoveredByTPM != f.KAT.ECC.Credential {
		t.Fatal("fixture says the TPM did not recover the credential")
	}
}

func TestMakeCredentialLayoutMatchesTheTPMsOwn(t *testing.T) {
	f := loadTPMFixture(t)
	for name, side := range map[string]tpmFixtureSide{"rsa": f.RSA, "ecc": f.ECC} {
		real := side.TPMMakeCredential
		mine, err := MakeCredential(b64(t, side.EKPublic), mustHex(t, side.AKName), mustHex(t, real.Credential), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(mine.CredentialBlob) != len(b64(t, real.CredentialBlob)) || len(mine.EncryptedSecret) != len(b64(t, real.EncryptedSecret)) {
			t.Fatalf("%s: layout differs from the blob the TPM itself made", name)
		}
	}
}

func TestMakeCredentialRefusals(t *testing.T) {
	f := loadTPMFixture(t)
	if _, err := MakeCredential(b64(t, f.RSA.AKPublic), mustHex(t, f.RSA.AKName), make([]byte, 32), nil); err == nil {
		t.Fatal("an AK was accepted as an EK")
	}
	for _, n := range []int{0, 33} {
		if _, err := MakeCredential(b64(t, f.RSA.EKPublic), mustHex(t, f.RSA.AKName), make([]byte, n), nil); err == nil {
			t.Fatalf("credential of %d bytes accepted", n)
		}
	}
}

var certifyKey = []byte("0123456789abcdef0123456789abcdef")

func buildCertifyEvidence(t *testing.T, f tpmFixtureSide, over map[string]any) (string, string) {
	t.Helper()
	nonce := string(mustHex(t, f.QualifyingData))
	ak, _ := ObjectName(b64(t, f.AKPublic))
	ek, _ := ObjectName(b64(t, f.EKPublic))
	secret := DeriveActivationSecret(certifyKey, nonce, ak, ek)
	ev := map[string]any{
		"ekPublic": f.EKPublic, "akPublic": f.AKPublic, "keyPublic": f.KeyPublic, "certifyInfo": f.CertifyInfo,
		"signature":  f.CertifySignature,
		"activation": map[string]any{"id": "act-1", "secret": hex.EncodeToString(secret)},
	}
	for k, v := range over {
		ev[k] = v
	}
	b, _ := json.Marshal(ev)
	return string(b), nonce
}

func thumbOf(t *testing.T, public string) string {
	t.Helper()
	pub, err := parseTPMPublic(b64(t, public))
	if err != nil {
		t.Fatal(err)
	}
	return tpmJWKThumbprint(pub)
}

func TestTPM2CertifyVerifiesRealOutput(t *testing.T) {
	f := loadTPMFixture(t)
	for name, side := range map[string]tpmFixtureSide{"rsa": f.RSA, "ecc": f.ECC} {
		t.Run(name, func(t *testing.T) {
			bind := BindNone
			if name == "ecc" {
				bind = BindAttestedKey
			}
			v, err := NewTPM2CertifyVerifier(TPM2CertifyOptions{AllowUnverifiedEK: true, Bind: bind})
			if err != nil {
				t.Fatal(err)
			}
			evidence, nonce := buildCertifyEvidence(t, side, nil)
			in := Input{Evidence: evidence, Nonce: nonce, ActivationKey: certifyKey}
			if name == "ecc" {
				in.CredentialKind, in.CredentialKeyThumbprint = "jwk", thumbOf(t, side.KeyPublic)
			}
			res, err := v(context.Background(), in)
			if err != nil || !res.OK {
				t.Fatalf("%+v %v", res, err)
			}
			if res.Claims["format"] != "tpm2-certify" || res.Claims["activated"] != true || res.Claims["ekVerified"] != false ||
				res.Claims["keyName"] != side.KeyName || res.Claims["akName"] != side.AKName {
				t.Fatalf("claims: %v", res.Claims)
			}
		})
	}
}

func TestTPM2CertifyRefusals(t *testing.T) {
	f := loadTPMFixture(t)
	v, _ := NewTPM2CertifyVerifier(TPM2CertifyOptions{AllowUnverifiedEK: true, Bind: BindNone})
	run := func(over map[string]any, mutate func(*Input)) Result {
		evidence, nonce := buildCertifyEvidence(t, f.ECC, over)
		in := Input{Evidence: evidence, Nonce: nonce, ActivationKey: certifyKey}
		if mutate != nil {
			mutate(&in)
		}
		res, err := v(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	want := func(res Result, reason string) {
		t.Helper()
		if res.OK || res.Reason != reason {
			t.Fatalf("got ok=%v %q, want %q", res.OK, res.Reason, reason)
		}
	}
	want(run(nil, func(in *Input) { in.Nonce = "another nonce here" }), "Certify qualifying data does not match the enrollment nonce")
	want(run(nil, func(in *Input) { in.ActivationKey = nil }), "TPM certify needs the activation service")
	want(run(nil, func(in *Input) { in.Nonce = "" }), "TPM certify needs the enrollment nonce")
	want(run(nil, func(in *Input) { in.ActivationKey = []byte("a different server secret value!!") }), "Credential activation is unknown, expired, used or wrong")
	info := b64(t, f.ECC.CertifyInfo)
	info[len(info)-3] ^= 1
	if res := run(map[string]any{"certifyInfo": b64s(info)}, nil); res.OK {
		t.Fatal("tampered certify info accepted")
	}
	sig := b64(t, f.ECC.CertifySignature)
	sig[len(sig)-2] ^= 1
	want(run(map[string]any{"signature": b64s(sig)}, nil), "Certify signature is invalid")
	if res := run(map[string]any{"keyPublic": f.RSA.KeyPublic}, nil); res.OK {
		t.Fatal("another key accepted")
	}
	// Bound to a key that is not the certified one.
	bound, _ := NewTPM2CertifyVerifier(TPM2CertifyOptions{AllowUnverifiedEK: true})
	evidence, nonce := buildCertifyEvidence(t, f.ECC, nil)
	res, _ := bound(context.Background(), Input{Evidence: evidence, Nonce: nonce, ActivationKey: certifyKey, CredentialKind: "jwk", CredentialKeyThumbprint: "x"})
	want(res, "Certified key is not the enrolled key")
	res, _ = bound(context.Background(), Input{Evidence: evidence, Nonce: nonce, ActivationKey: certifyKey, CredentialKind: "psk"})
	want(res, "Enroll a jwk credential: the certified TPM key must be the enrolled key")
	if _, err := NewTPM2CertifyVerifier(TPM2CertifyOptions{}); err == nil {
		t.Fatal("verifier without roots or opt out accepted")
	}
}

func TestDeriveActivationSecretIsBound(t *testing.T) {
	a := DeriveActivationSecret(certifyKey, "n1", []byte("ak"), []byte("ek"))
	for _, other := range [][]byte{
		DeriveActivationSecret(certifyKey, "n2", []byte("ak"), []byte("ek")),
		DeriveActivationSecret(certifyKey, "n1", []byte("ak2"), []byte("ek")),
		DeriveActivationSecret(certifyKey, "n1", []byte("ak"), []byte("ek2")),
		DeriveActivationSecret([]byte("another key another key another"), "n1", []byte("ak"), []byte("ek")),
	} {
		if string(a) == string(other) {
			t.Fatal("activation secret is not bound to its inputs")
		}
	}
	if len(a) != sha256.Size {
		t.Fatalf("length %d", len(a))
	}
}
