package as_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/iot/attest"
)

// e2e_device_tpm_test.go: TPM 2.0 credential activation through enrollment, with a software TPM
// simulated in the test (a software EK, AK and key with the structures a real TPM writes). The same
// verifier and MakeCredential run against real swtpm output in iot/attest.

func be16(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

func tpmSized(b []byte) []byte { return append(be16(len(b)), b...) }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// eccPublic builds a TPMT_PUBLIC of a P-256 key. scheme is 0x0018 (ECDSA SHA-256) or 0 for NULL.
func eccPublic(x, y *big.Int, attrs uint32, scheme int) []byte {
	var sc []byte
	if scheme == 0 {
		sc = be16(0x0010)
	} else {
		sc = cat(be16(scheme), be16(0x000b))
	}
	xb, yb := make([]byte, 32), make([]byte, 32)
	x.FillBytes(xb)
	y.FillBytes(yb)
	return cat(be16(0x0023), be16(0x000b), binary.BigEndian.AppendUint32(nil, attrs), tpmSized(nil),
		be16(0x0010), sc, be16(3), be16(0x0010), tpmSized(xb), tpmSized(yb))
}

// rsaEKPublic builds the TPMT_PUBLIC of an RSA 2048 endorsement key (AES 128 CFB, no scheme).
func rsaEKPublic(n *big.Int) []byte {
	nb := make([]byte, 256)
	n.FillBytes(nb)
	attrs := uint32(0x2 | 0x10 | 0x10000 | 0x20000 | 0x20 | 0x40)
	return cat(be16(0x0001), be16(0x000b), binary.BigEndian.AppendUint32(nil, attrs), tpmSized(nil),
		be16(0x0006), be16(128), be16(0x0043), be16(0x0010), be16(2048), binary.BigEndian.AppendUint32(nil, 0), tpmSized(nb))
}

func tpmName(pub []byte) []byte {
	h := sha256.Sum256(pub)
	return cat(be16(0x000b), h[:])
}

func kdfa(key []byte, label string, ctxU []byte, bits int) []byte {
	var out []byte
	for i := uint32(1); len(out) < (bits+7)/8; i++ {
		m := hmac.New(sha256.New, key)
		m.Write(cat(binary.BigEndian.AppendUint32(nil, i), []byte(label), []byte{0}, ctxU, binary.BigEndian.AppendUint32(nil, uint32(bits))))
		out = append(out, m.Sum(nil)...)
	}
	return out[:(bits+7)/8]
}

// softwareActivate is TPM2_ActivateCredential for a software RSA EK: the reverse of MakeCredential.
func softwareActivate(t *testing.T, ek *rsa.PrivateKey, akName, blob, encSecret []byte) []byte {
	t.Helper()
	seed, err := rsa.DecryptOAEP(sha256.New(), nil, ek, encSecret[2:], append([]byte("IDENTITY"), 0))
	if err != nil {
		t.Fatal(err)
	}
	idObj := blob[2:]
	macLen := int(binary.BigEndian.Uint16(idObj))
	mac, enc := idObj[2:2+macLen], idObj[2+macLen:]
	hk := kdfa(seed, "INTEGRITY", nil, 256)
	m := hmac.New(sha256.New, hk)
	m.Write(cat(enc, akName))
	if !hmac.Equal(m.Sum(nil), mac) {
		t.Fatal("credential integrity check failed")
	}
	block, _ := aes.NewCipher(kdfa(seed, "STORAGE", akName, 128))
	plain := make([]byte, len(enc))
	//nolint:staticcheck // TPM 2.0 credential protection is specified as AES-CFB, there is no choice of mode.
	cipher.NewCFBDecrypter(block, make([]byte, 16)).XORKeyStream(plain, enc)
	return plain[2:]
}

func TestDeviceTPMCertifyThroughEnrollment(t *testing.T) {
	verify, err := attest.NewTPM2CertifyVerifier(attest.TPM2CertifyOptions{AllowUnverifiedEK: true})
	if err != nil {
		t.Fatal(err)
	}
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{Attestation: &theauth.DeviceAttestationConfig{Required: true, Verify: verify}})

	// The software TPM: EK (RSA), AK (ECC restricted signing) and the device key it certifies.
	ek, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ekPub := rsaEKPublic(ek.N)
	akPub := eccPublic(ak.X, ak.Y, 0x2|0x10|0x20|0x40|0x10000|0x40000, 0x0018)
	akName := tpmName(akPub)

	enrollWith := func(t *testing.T, devKeyPair devKey, joinToken string, secretFor func(blob, enc []byte) []byte) (int, map[string]any) {
		t.Helper()
		code, ch := h.challenge(t, joinToken, devKeyPair)
		if code != http.StatusOK {
			t.Fatalf("challenge: %d", code)
		}
		nonce := nonceOf(t, ch)
		proof := h.proof(t, devKeyPair, ch)
		code, act := postJSON(t, h.srv.URL+"/oauth/devices/tpm-activation", map[string]any{
			"join_token": joinToken, "jwk": devKeyPair.jwkJSON(), "challenge": ch, "proof": proof,
			"ek_public": base64.RawURLEncoding.EncodeToString(ekPub), "ak_public": base64.RawURLEncoding.EncodeToString(akPub),
		})
		if code != http.StatusOK {
			t.Fatalf("tpm-activation: %d %v", code, act)
		}
		blob, _ := base64.RawURLEncoding.DecodeString(act["credential_blob"].(string))
		enc, _ := base64.RawURLEncoding.DecodeString(act["encrypted_secret"].(string))
		secret := secretFor(blob, enc)

		// TPM2_Certify of the device key, signed by the AK, with the nonce as qualifying data.
		devX, _ := new(big.Int).SetString(hex.EncodeToString(mustB64(t, devKeyPair.jwk["x"])), 16)
		devY, _ := new(big.Int).SetString(hex.EncodeToString(mustB64(t, devKeyPair.jwk["y"])), 16)
		keyPub := eccPublic(devX, devY, 0x2|0x10|0x20|0x40|0x40000, 0)
		keyName := tpmName(keyPub)
		info := cat(binary.BigEndian.AppendUint32(nil, 0xff544347), be16(0x8017), tpmSized(akName), tpmSized([]byte(nonce)),
			make([]byte, 8), make([]byte, 4), make([]byte, 4), []byte{1}, make([]byte, 8), tpmSized(keyName), tpmSized(keyName))
		digest := sha256.Sum256(info)
		r, s, err := ecdsa.Sign(rand.Reader, ak, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		rb, sb := make([]byte, 32), make([]byte, 32)
		r.FillBytes(rb)
		s.FillBytes(sb)
		sig := cat(be16(0x0018), be16(0x000b), tpmSized(rb), tpmSized(sb))
		b64 := base64.RawURLEncoding.EncodeToString
		evidence, _ := json.Marshal(map[string]any{
			"ekPublic": b64(ekPub), "akPublic": b64(akPub), "keyPublic": b64(keyPub), "certifyInfo": b64(info), "signature": b64(sig),
			"activation": map[string]any{"id": "simulated", "secret": hex.EncodeToString(secret)},
		})
		return postJSON(t, h.srv.URL+"/oauth/devices/enroll", map[string]any{
			"join_token": joinToken, "jwk": devKeyPair.jwkJSON(), "challenge": ch, "proof": proof, "attestation_evidence": string(evidence),
		})
	}

	key := newES256DevKey(t)
	_, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{Name: "tpm-robot"})
	var recovered []byte
	code, body := enrollWith(t, key, secret, func(blob, enc []byte) []byte {
		recovered = softwareActivate(t, ek, akName, blob, enc)
		return recovered
	})
	if code != http.StatusCreated {
		t.Fatalf("enroll: %d %v", code, body)
	}
	devs, _ := h.a.ListDevices(context.Background(), &h.org)
	if len(devs) != 1 || devs[0].AttestationClaims["format"] != "tpm2-certify" || devs[0].AttestationClaims["activated"] != true {
		t.Fatalf("stored claims: %+v", devs)
	}
	if facts, ok := attest.FactsFromClaims(devs[0].AttestationClaims); !ok || facts.SecurityLevel != "software" {
		t.Fatalf("an EK nobody vouches for must not read as hardware: %+v", facts)
	}

	// A secret recovered for the first enrollment is worthless in a second one (another nonce).
	key2 := newES256DevKey(t)
	_, secret2 := h.mint(t, theauth.CreateDeviceJoinTokenInput{Name: "tpm-robot-2"})
	code, body = enrollWith(t, key2, secret2, func(_, _ []byte) []byte { return recovered })
	if code != http.StatusBadRequest || body["error_description"] != "attestation_failed: Credential activation is unknown, expired, used or wrong" {
		t.Fatalf("replayed secret: %d %v", code, body)
	}
	// A wrong secret, too.
	key3 := newES256DevKey(t)
	_, secret3 := h.mint(t, theauth.CreateDeviceJoinTokenInput{Name: "tpm-robot-3"})
	code, _ = enrollWith(t, key3, secret3, func(_, _ []byte) []byte { return make([]byte, 32) })
	if code != http.StatusBadRequest {
		t.Fatalf("wrong secret: %d", code)
	}
	if devs, _ = h.a.ListDevices(context.Background(), &h.org); len(devs) != 1 {
		t.Fatalf("refused enrollments created devices: %d", len(devs))
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
