package as_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/iot/attest"
)

// e2e_device_appattest_test.go: Apple App Attest assertions from an enrolled device, with the counter
// stored atomically. The real recording is veehaitch/devicecheck-appattest (Apache-2.0).

func readAssertionFixture(t *testing.T) (att struct {
	Attestation, KeyID, AppID, Nonce, CheckTime string
}, asr struct{ Assertion, ClientData string }) {
	t.Helper()
	raw, err := os.ReadFile("../../iot/attest/testdata/apple-app-attest.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Fixtures map[string]struct {
			Attestation string `json:"attestation"`
			KeyID       string `json:"keyId"`
			AppID       string `json:"appId"`
			Nonce       string `json:"nonce"`
			CheckTime   string `json:"checkTime"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	v := f.Fixtures["veehaitch_ios_14_4"]
	att.Attestation, att.KeyID, att.AppID, att.Nonce, att.CheckTime = v.Attestation, v.KeyID, v.AppID, v.Nonce, v.CheckTime
	raw, err = os.ReadFile("../../iot/attest/testdata/apple-app-assertion.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Assertions map[string]struct {
			Assertion  string `json:"assertion"`
			ClientData string `json:"clientData"`
		} `json:"assertions"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	a := g.Assertions["veehaitch_ios_14_4"]
	asr.Assertion, asr.ClientData = a.Assertion, a.ClientData
	return
}

func enrolledDevice(t *testing.T, h *iotHarness, evidence string) theauth.Device {
	t.Helper()
	_, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{Name: "phone"})
	code, body := h.enrollWithEvidence(t, secret, newES256DevKey(t), evidence)
	if code != http.StatusCreated {
		t.Fatalf("enroll: %d %v", code, body)
	}
	devs, err := h.a.ListDevices(context.Background(), &h.org)
	if err != nil || len(devs) == 0 {
		t.Fatalf("list: %v %v", devs, err)
	}
	return devs[0]
}

func TestDeviceAppAssertionRealRecordingEndToEnd(t *testing.T) {
	att, asr := readAssertionFixture(t)
	checkTime, err := time.Parse(time.RFC3339, att.CheckTime)
	if err != nil {
		t.Fatal(err)
	}
	verify, err := attest.NewAppleAppAttestVerifier(attest.AppleAppAttestOptions{
		AppIDs: []string{att.AppID}, Environment: attest.AppleDevelopment, Bind: attest.BindNone,
		Now: func() time.Time { return checkTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{Attestation: &theauth.DeviceAttestationConfig{
		Required: true,
		// The recording used its own challenge, so the enrollment nonce is swapped for it.
		Verify: func(ctx context.Context, in attest.Input) (attest.Result, error) {
			in.Nonce = att.Nonce
			return verify(ctx, in)
		},
	}})
	evidence, _ := json.Marshal(map[string]string{"attestation": att.Attestation, "keyId": att.KeyID})
	dev := enrolledDevice(t, h, string(evidence))
	if dev.AttestationClaims["attestedPublicKey"] == nil || dev.AppAttestCounter != 0 {
		t.Fatalf("stored device: %+v", dev)
	}
	req := theauth.DeviceAppAssertionRequest{Assertion: asr.Assertion, ClientData: []byte(asr.ClientData)}
	got, err := h.a.VerifyDeviceAppAssertion(context.Background(), dev.ID, req)
	if err != nil || got.AppAttestCounter != 1 {
		t.Fatalf("first: %+v %v", got, err)
	}
	_, err = h.a.VerifyDeviceAppAssertion(context.Background(), dev.ID, req)
	var ae *theauth.DeviceAppAssertionError
	if !errors.As(err, &ae) || ae.Code != "assertion_replayed" || !errors.Is(err, theauth.ErrDeviceAppAssertion) {
		t.Fatalf("replay: %v", err)
	}
	stored, _ := h.a.ListDevices(context.Background(), &h.org)
	if stored[0].AppAttestCounter != 1 {
		t.Fatalf("stored counter %d", stored[0].AppAttestCounter)
	}
}

// simulatedAppAttestDevice enrolls a device whose verifier reports a local P-256 key, so racing and
// counter gaps can be tested with assertions made on the fly.
func simulatedAppAttestDevice(t *testing.T) (*iotHarness, theauth.Device, func(clientData string, counter uint32) string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y) //nolint:staticcheck // raw X9.62 point is the claim format
	appID := "TEAMID1234.com.example.sim"
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{Attestation: &theauth.DeviceAttestationConfig{
		Required: true,
		Verify: func(context.Context, attest.Input) (attest.Result, error) {
			return attest.Result{OK: true, Claims: map[string]any{
				"format": "apple-app-attest", "appId": appID, "attestedPublicKey": base64.StdEncoding.EncodeToString(point),
			}}, nil
		},
	}})
	dev := enrolledDevice(t, h, `{"x":1}`)
	sign := func(clientData string, counter uint32) string {
		rp := sha256.Sum256([]byte(appID))
		auth := make([]byte, 37)
		copy(auth, rp[:])
		binary.BigEndian.PutUint32(auth[33:], counter)
		cdh := sha256.Sum256([]byte(clientData))
		nonce := sha256.Sum256(append(append([]byte{}, auth...), cdh[:]...))
		digest := sha256.Sum256(nonce[:])
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			t.Fatal(err)
		}
		cbor := []byte{0xa2, 0x60 + 9}
		cbor = append(cbor, "signature"...)
		cbor = append(cbor, 0x58, byte(len(sig)))
		cbor = append(cbor, sig...)
		cbor = append(cbor, 0x60+17)
		cbor = append(cbor, "authenticatorData"...)
		cbor = append(cbor, 0x58, byte(len(auth)))
		cbor = append(cbor, auth...)
		return base64.StdEncoding.EncodeToString(cbor)
	}
	return h, dev, sign
}

func TestDeviceAppAssertionCounterGapsAndRefusals(t *testing.T) {
	h, dev, sign := simulatedAppAttestDevice(t)
	ctx := context.Background()
	run := func(n uint32) (theauth.Device, error) {
		cd := "c" + string(rune('a'+n))
		return h.a.VerifyDeviceAppAssertion(ctx, dev.ID, theauth.DeviceAppAssertionRequest{Assertion: sign(cd, n), ClientData: []byte(cd)})
	}
	if _, err := run(1); err != nil {
		t.Fatal(err)
	}
	if d, err := run(5); err != nil || d.AppAttestCounter != 5 {
		t.Fatalf("gap: %+v %v", d, err)
	}
	for _, n := range []uint32{5, 3} {
		var ae *theauth.DeviceAppAssertionError
		if _, err := run(n); !errors.As(err, &ae) || ae.Code != "assertion_replayed" {
			t.Fatalf("counter %d: %v", n, err)
		}
	}
	if _, err := run(6); err != nil {
		t.Fatal(err)
	}
	// Wrong client data: signature invalid, counter untouched.
	var ae *theauth.DeviceAppAssertionError
	_, err := h.a.VerifyDeviceAppAssertion(ctx, dev.ID, theauth.DeviceAppAssertionRequest{Assertion: sign("one", 9), ClientData: []byte("two")})
	if !errors.As(err, &ae) || ae.Code != "assertion_invalid" {
		t.Fatalf("tampered: %v", err)
	}
	// Unknown and revoked devices.
	_, err = h.a.VerifyDeviceAppAssertion(ctx, theauth.ULID{}, theauth.DeviceAppAssertionRequest{})
	if !errors.As(err, &ae) || ae.Code != "device_not_found" {
		t.Fatalf("unknown: %v", err)
	}
	if err := h.a.RevokeDevice(ctx, dev.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err = run(20)
	if !errors.As(err, &ae) || ae.Code != "device_blocked" {
		t.Fatalf("revoked: %v", err)
	}
}

func TestDeviceAppAssertionRaceLetsOneThrough(t *testing.T) {
	h, dev, sign := simulatedAppAttestDevice(t)
	req := theauth.DeviceAppAssertionRequest{Assertion: sign("race", 7), ClientData: []byte("race")}
	var wins, replays atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.a.VerifyDeviceAppAssertion(context.Background(), dev.ID, req)
			var ae *theauth.DeviceAppAssertionError
			switch {
			case err == nil:
				wins.Add(1)
			case errors.As(err, &ae) && ae.Code == "assertion_replayed":
				replays.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || replays.Load() != 15 {
		t.Fatalf("wins %d replays %d", wins.Load(), replays.Load())
	}
}

func TestDeviceWithoutAppAttestKeyIsRefused(t *testing.T) {
	h := newIoTHarness(t, nil)
	_, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{Name: "plain"})
	code, body := h.enrollWithEvidence(t, secret, newES256DevKey(t), "")
	if code != http.StatusCreated {
		t.Fatalf("enroll: %d %v", code, body)
	}
	devs, _ := h.a.ListDevices(context.Background(), &h.org)
	_, err := h.a.VerifyDeviceAppAssertion(context.Background(), devs[0].ID, theauth.DeviceAppAssertionRequest{Assertion: "AAAA"})
	var ae *theauth.DeviceAppAssertionError
	if !errors.As(err, &ae) || ae.Code != "not_app_attest" {
		t.Fatalf("got %v", err)
	}
}
