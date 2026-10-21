package attest

import (
	"testing"
)

func TestConstructorsRefuseBadOptions(t *testing.T) {
	if _, err := NewAndroidKeyVerifier(AndroidKeyOptions{RevocationDisabled: true, BootPolicy: "sometimes"}); err == nil {
		t.Fatal("unknown boot policy accepted")
	}
	if _, err := NewAndroidKeyVerifier(AndroidKeyOptions{RevocationDisabled: true, MinSecurityLevel: "software"}); err == nil {
		t.Fatal("software level accepted as a minimum")
	}
	if _, err := NewAndroidKeyVerifier(AndroidKeyOptions{RevocationDisabled: true, Roots: []string{"not a cert"}}); err == nil {
		t.Fatal("garbage trust anchor accepted")
	}
	if _, err := NewAppleAppAttestVerifier(AppleAppAttestOptions{Bind: "maybe"}); err == nil {
		t.Fatal("unknown bind accepted")
	}
	if _, err := NewAppleAppAttestVerifier(AppleAppAttestOptions{Environment: "staging"}); err == nil {
		t.Fatal("unknown environment accepted")
	}
	if _, err := NewTPM2QuoteVerifier(TPM2Options{AllowUnverifiedAk: true, ExpectedPCRs: map[string]map[int]string{"md5": {0: "00"}}}); err == nil {
		t.Fatal("unknown PCR bank accepted")
	}
}

func TestBundledRoots(t *testing.T) {
	if len(GoogleAttestationRoots) != 2 || len(AppleAppAttestRoots) != 1 {
		t.Fatalf("roots: %d google, %d apple", len(GoogleAttestationRoots), len(AppleAppAttestRoots))
	}
	first, err := parseCertText(GoogleAttestationRoots[0])
	if err != nil || first.subjectSerialNumber != googleFactoryRoot {
		t.Fatalf("first google root: %v %q", err, first.subjectSerialNumber)
	}
	if _, err := parseCertText(AppleAppAttestRoots[0]); err != nil {
		t.Fatal(err)
	}
}

func TestSerialHexMatchesRevocationListForm(t *testing.T) {
	f := loadFixtures(t)
	der, err := certBytesFromText(f.android.Chains["algorithm_EC_SecurityLevel_TEE"][2])
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if c.serialHex != "388266760658996857d" {
		t.Fatalf("serial = %s", c.serialHex)
	}
}

func TestParsersRefuseHostileInput(t *testing.T) {
	for _, in := range [][]byte{nil, {0x30}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, {0x30, 0x80}, {0x1f, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00}} {
		if _, _, err := readTLV(in); err == nil {
			t.Fatalf("readTLV accepted %x", in)
		}
	}
	for _, in := range [][]byte{nil, {0x5f}, {0x9f, 0x00}, {0xbf}, {0xa2, 0x01, 0x01, 0x01, 0x02}, {0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, {0xf9, 0x00, 0x00}} {
		if _, err := decodeCBORExact(in); err == nil {
			t.Fatalf("CBOR accepted %x", in)
		}
	}
	// Deeply nested arrays hit the depth cap instead of the stack.
	deep := make([]byte, 40)
	for i := range deep {
		deep[i] = 0x81
	}
	deep = append(deep, 0x00)
	if _, err := decodeCBORExact(deep); err == nil {
		t.Fatal("deep nesting accepted")
	}
}

func FuzzParseCertificate(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	fx := loadFixtures(f)
	for _, c := range fx.android.Chains["algorithm_EC_SecurityLevel_TEE"][:1] {
		if der, err := certBytesFromText(c); err == nil {
			f.Add(der)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if c, err := parseCertificate(data); err == nil && c.der == nil {
			t.Fatal("nil der")
		}
	})
}

func FuzzParseTPM(f *testing.F) {
	f.Add([]byte{0xff, 0x54, 0x43, 0x47, 0x80, 0x18})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseTPMQuote(data)
		_, _ = parseTPMPublic(data)
		_, _ = parseTPMSignature(data)
		_, _ = decodeCBORExact(data)
	})
}
