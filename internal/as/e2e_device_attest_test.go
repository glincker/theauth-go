package as_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/iot/attest"
)

// e2e_device_attest_test.go: the hardware attestation hook of device enrollment.

// enrollWithEvidence runs challenge, proof and enroll, adding attestation_evidence. It returns
// the challenge response nonce too.
func (h *iotHarness) enrollWithEvidence(t *testing.T, joinToken string, key devKey, evidence string) (int, map[string]any) {
	t.Helper()
	code, body := postJSON(t, h.srv.URL+"/oauth/devices/challenge", map[string]any{"join_token": joinToken, "jwk": key.jwkJSON()})
	if code != http.StatusOK {
		t.Fatalf("challenge: %d %v", code, body)
	}
	ch := body["challenge"].(string)
	if body["nonce"] != nonceOf(t, ch) {
		t.Fatalf("challenge nonce %v is not the challenge jti %s", body["nonce"], nonceOf(t, ch))
	}
	req := map[string]any{"join_token": joinToken, "jwk": key.jwkJSON(), "challenge": ch, "proof": h.proof(t, key, ch)}
	if evidence != "" {
		req["attestation_evidence"] = evidence
	}
	return postJSON(t, h.srv.URL+"/oauth/devices/enroll", req)
}

func p256Thumbprint(k devKey) string {
	canonical := `{"crv":"` + k.jwk["crv"] + `","kty":"EC","x":"` + k.jwk["x"] + `","y":"` + k.jwk["y"] + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestDeviceAttestationVerifierGetsNonceAndKey(t *testing.T) {
	var got attest.Input
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{Attestation: &theauth.DeviceAttestationConfig{
		Required: true,
		Verify: func(_ context.Context, in attest.Input) (attest.Result, error) {
			got = in
			return attest.Result{OK: true, Claims: map[string]any{"format": "test"}}, nil
		},
	}})
	key := newES256DevKey(t)
	_, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{Name: "robot"})
	code, body := h.enrollWithEvidence(t, secret, key, `{"any":"thing"}`)
	if code != http.StatusCreated {
		t.Fatalf("enroll: %d %v", code, body)
	}
	if got.Evidence != `{"any":"thing"}` || got.Nonce == "" || got.CredentialKind != "jwk" ||
		got.CredentialKeyThumbprint != p256Thumbprint(key) || got.EnrollmentID == "" {
		t.Fatalf("verifier input: %+v", got)
	}
	devs, err := h.a.ListDevices(context.Background(), &h.org)
	if err != nil || len(devs) != 1 || devs[0].AttestationClaims["format"] != "test" {
		t.Fatalf("claims were not stored on the device record: %+v %v", devs, err)
	}
}

func TestDeviceAttestationRequiredAndRefusalsDoNotSpendTheToken(t *testing.T) {
	var mode atomic.Int32 // 0 refuse, 1 error, 2 panic, 3 accept
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{Attestation: &theauth.DeviceAttestationConfig{
		Required: true,
		Verify: func(context.Context, attest.Input) (attest.Result, error) {
			switch mode.Load() {
			case 0:
				return attest.Result{Reason: "Attestation challenge does not match the enrollment nonce"}, nil
			case 1:
				return attest.Result{}, errors.New("revocation list down")
			case 2:
				panic("boom")
			}
			return attest.Result{OK: true}, nil
		},
	}})
	key := newES256DevKey(t)
	_, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{Name: "robot"})

	code, body := h.enrollWithEvidence(t, secret, key, "")
	if code != http.StatusBadRequest || body["error_description"] != "attestation_required" {
		t.Fatalf("missing evidence: %d %v", code, body)
	}
	code, body = h.enrollWithEvidence(t, secret, key, "{}")
	if code != http.StatusBadRequest || body["error"] != "invalid_grant" ||
		body["error_description"] != "attestation_failed: Attestation challenge does not match the enrollment nonce" {
		t.Fatalf("refused evidence: %d %v", code, body)
	}
	for _, m := range []int32{1, 2} {
		mode.Store(m)
		code, body = h.enrollWithEvidence(t, secret, key, "{}")
		if code != http.StatusBadRequest || body["error_description"] != "attestation_failed" {
			t.Fatalf("mode %d: %d %v", m, code, body)
		}
	}
	mode.Store(3)
	if code, body = h.enrollWithEvidence(t, secret, key, "{}"); code != http.StatusCreated {
		t.Fatalf("the same join token must still work after refusals: %d %v", code, body)
	}
}

func TestDeviceAttestationOptionalAndUnconfigured(t *testing.T) {
	// Not required: no evidence enrolls, evidence that is sent must pass.
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{Attestation: &theauth.DeviceAttestationConfig{
		Verify: func(context.Context, attest.Input) (attest.Result, error) { return attest.Result{Reason: "no"}, nil },
	}})
	key := newES256DevKey(t)
	_, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{Name: "a"})
	if code, body := h.enrollWithEvidence(t, secret, key, "{}"); code != http.StatusBadRequest {
		t.Fatalf("bad evidence must fail even when optional: %d %v", code, body)
	}
	if code, body := h.enrollWithEvidence(t, secret, key, ""); code != http.StatusCreated {
		t.Fatalf("no evidence, not required: %d %v", code, body)
	}

	// No hook at all: evidence is refused, not ignored.
	h2 := newIoTHarness(t, nil)
	_, secret2 := h2.mint(t, theauth.CreateDeviceJoinTokenInput{Name: "b"})
	code, body := h2.enrollWithEvidence(t, secret2, newES256DevKey(t), "{}")
	if code != http.StatusBadRequest || body["error_description"] != "attestation_failed: No attestation verifier is configured" {
		t.Fatalf("unconfigured: %d %v", code, body)
	}
}

// TestDeviceAttestationRealAndroidChainBoundToNonce sends a real vendor chain (Google's
// android-key-attestation fixtures, challenge "abc") through the HTTP enrollment. The challenge
// is not the enrollment nonce, so the real verifier must refuse it with its own reason.
func TestDeviceAttestationRealAndroidChainBoundToNonce(t *testing.T) {
	raw, err := os.ReadFile("../../iot/attest/testdata/android-key-attestation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Chains map[string][]string `json:"chains"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	evidence, _ := json.Marshal(fx.Chains["algorithm_EC_SecurityLevel_TEE"])
	verify, err := attest.NewAndroidKeyVerifier(attest.AndroidKeyOptions{
		RevocationDisabled: true, BootPolicy: "any", BindKey: attest.Bool(false),
		Now: func() time.Time { return time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{Attestation: &theauth.DeviceAttestationConfig{Required: true, Verify: verify}})
	_, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{Name: "phone"})
	code, body := h.enrollWithEvidence(t, secret, newES256DevKey(t), string(evidence))
	if code != http.StatusBadRequest ||
		body["error_description"] != "attestation_failed: Attestation challenge does not match the enrollment nonce" {
		t.Fatalf("real chain: %d %v", code, body)
	}
}
