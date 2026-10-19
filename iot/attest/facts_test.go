package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/iot/device"
)

// testdata/facts-vectors.json comes from the TypeScript attestationFacts over claims of the real
// vendor fixtures plus hand written edge claims (docs-local/vectors/gen-attest-policy-vectors.mts).
func TestFactsFromClaimsMatchesTypeScript(t *testing.T) {
	raw, err := os.ReadFile("testdata/facts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name   string         `json:"name"`
			Claims map[string]any `json:"claims"`
			Facts  map[string]any `json:"facts"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) < 25 {
		t.Fatalf("only %d vectors", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			got, ok := FactsFromClaims(v.Claims)
			if v.Facts == nil {
				if ok {
					t.Fatalf("expected no facts, got %+v", got)
				}
				return
			}
			if !ok {
				t.Fatalf("no facts, TS has %v", v.Facts)
			}
			// Compare through JSON so slices and numbers have one shape.
			gb, _ := json.Marshal(got.Map())
			var gm map[string]any
			_ = json.Unmarshal(gb, &gm)
			if !reflect.DeepEqual(gm, v.Facts) {
				t.Fatalf("got %v, TS says %v", gm, v.Facts)
			}
		})
	}
}

// Claims straight from a verifier hold typed slices, claims read from storage hold decoded JSON.
func TestFactsFromClaimsAcceptsBothShapes(t *testing.T) {
	typed, _ := FactsFromClaims(map[string]any{"format": "android-key-attestation", "securityLevel": "strongbox", "packages": []string{"a"}})
	decoded, _ := FactsFromClaims(map[string]any{"format": "android-key-attestation", "securityLevel": "strongbox", "packages": []any{"a"}})
	if !reflect.DeepEqual(typed, decoded) || typed.SecurityLevel != device.LevelStrongbox || len(typed.AppIDs) != 1 {
		t.Fatalf("%+v vs %+v", typed, decoded)
	}
}

// A device enrolled with strongbox evidence signs the facts into its bundle, and the device decides a
// permission with an attestation constraint from them, offline.
func TestAttestationFactsRideInASignedBundle(t *testing.T) {
	claims := map[string]any{
		"format": "android-key-attestation", "securityLevel": "strongbox", "keySecurityLevel": "strongbox",
		"verifiedBootState": "verified", "deviceLocked": true, "packages": []string{"com.example.lock"},
	}
	facts, ok := FactsFromClaims(claims)
	if !ok {
		t.Fatal("no facts")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := device.NewSigner(priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0)
	bundle := func(f *device.AttestationFacts) *device.Claims {
		tok, err := signer.SignBundle("k1", device.Claims{
			Issuer: device.DefaultIssuer, Subject: "dev-1", Audience: "dev-1", IssuedAt: now.Unix(), NotBefore: now.Unix(),
			Exp: now.Add(time.Hour).Unix(), JTI: "j", Seq: 1,
			Perms: []device.Permission{{Resource: "door:*", Actions: []string{"unlock"}, Constraints: &device.Constraints{
				Attestation: device.NewAttestationConstraint(device.LevelStrongbox, []string{device.BootVerified}, []string{"com.example.lock"}),
			}}},
			Attestation: f,
		})
		if err != nil {
			t.Fatal(err)
		}
		pub := signer.Public()
		pub.KID = "k1"
		got, err := device.VerifyBundle(tok, device.VerifyOptions{Keys: device.NewKeySet(pub), DeviceID: "dev-1", Now: now})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if d := device.Evaluate(bundle(&facts), "unlock", "door:front", device.WithNow(now)); !d.Allowed {
		t.Fatalf("strongbox bundle denied: %+v", d)
	}
	weaker := facts
	weaker.SecurityLevel = device.LevelHardware
	if d := device.Evaluate(bundle(&weaker), "unlock", "door:front", device.WithNow(now)); d.Allowed || d.Code != device.CodeAttestationRequired {
		t.Fatalf("hardware bundle: %+v", d)
	}
	if d := device.Evaluate(bundle(nil), "unlock", "door:front", device.WithNow(now)); d.Allowed || d.Code != device.CodeAttestationRequired {
		t.Fatalf("bundle without facts: %+v", d)
	}
}
