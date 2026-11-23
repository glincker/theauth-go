package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testdata = "../../iot/attest/testdata/"

func deviceRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"device", "attest"}, args...), &out, &errb, zeros{})
	return code, out.String(), errb.String()
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fixtureJSON(t *testing.T, file string, into any) {
	t.Helper()
	b, err := os.ReadFile(testdata + file)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceAttestApple(t *testing.T) {
	var f struct {
		Fixtures map[string]struct {
			Attestation string `json:"attestation"`
			KeyID       string `json:"keyId"`
			AppID       string `json:"appId"`
			Nonce       string `json:"nonce"`
			CheckTime   string `json:"checkTime"`
		} `json:"fixtures"`
	}
	fixtureJSON(t, "apple-app-attest.json", &f)
	v := f.Fixtures["veehaitch_ios_14_4"]
	evidence, _ := json.Marshal(map[string]string{"attestation": v.Attestation, "keyId": v.KeyID})
	ev := writeTemp(t, "evidence.json", string(evidence))
	common := []string{"apple", "--evidence", ev, "--nonce", v.Nonce, "--app-id", v.AppID, "--environment", "development", "--now", v.CheckTime}
	code, out, errb := deviceRun(t, common...)
	if code != 0 || !strings.HasPrefix(out, "Accepted") || !strings.Contains(out, `appId: "`+v.AppID+`"`) ||
		!strings.Contains(out, `Policy facts: {"appIds":["`+v.AppID+`"],"format":"apple-app-attest","securityLevel":"hardware"}`) {
		t.Fatalf("accepted: %d %q %q", code, out, errb)
	}
	code, out, _ = deviceRun(t, append(common, "--json")...)
	var j struct {
		OK     bool           `json:"ok"`
		Claims map[string]any `json:"claims"`
		Facts  map[string]any `json:"facts"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &j) != nil || !j.OK || j.Facts["securityLevel"] != "hardware" || j.Claims["attestedPublicKey"] == nil {
		t.Fatalf("json: %d %q", code, out)
	}
	// Wrong nonce is refused with exit code 1 and the same sentence the enrollment hook gives.
	bad := append([]string{}, common...)
	bad[4] = "another nonce"
	if code, out, _ = deviceRun(t, bad...); code != 1 || !strings.HasPrefix(out, "Refused: ") {
		t.Fatalf("refused: %d %q", code, out)
	}
	// Usage errors exit 2.
	if code, _, errb = deviceRun(t, "apple", "--evidence", ev, "--nonce", "n"); code != 2 || !strings.Contains(errb, "--app-id") {
		t.Fatalf("usage: %d %q", code, errb)
	}
	if code, _, _ = deviceRun(t, "nope"); code != 2 {
		t.Fatalf("unknown format: %d", code)
	}
}

func TestDeviceAttestAppleAssertionAndReceipt(t *testing.T) {
	var a struct {
		Assertions map[string]struct {
			Assertion  string `json:"assertion"`
			ClientData string `json:"clientData"`
			AppID      string `json:"appId"`
			PublicKey  string `json:"publicKey"`
			Counter    int    `json:"counter"`
		} `json:"assertions"`
		Receipts map[string]struct {
			Receipt string `json:"receipt"`
			AppID   string `json:"appId"`
		} `json:"receipts"`
	}
	fixtureJSON(t, "apple-app-assertion.json", &a)
	v := a.Assertions["veehaitch_ios_14_4"]
	af := writeTemp(t, "assertion.b64", v.Assertion+"\n")
	cf := writeTemp(t, "client-data", v.ClientData)
	code, out, errb := deviceRun(t, "apple-assertion", "--assertion", af, "--client-data", cf, "--app-id", v.AppID, "--public-key", v.PublicKey, "--previous-counter", "0")
	if code != 0 || !strings.Contains(out, "counter: 1") {
		t.Fatalf("assertion: %d %q %q", code, out, errb)
	}
	code, out, _ = deviceRun(t, "apple-assertion", "--assertion", af, "--client-data", cf, "--app-id", v.AppID, "--public-key", v.PublicKey, "--previous-counter", "1")
	if code != 1 || out != "Refused: Assertion counter did not increase\n" {
		t.Fatalf("replay: %d %q", code, out)
	}
	r := a.Receipts["veehaitch_attest_receipt"]
	rf := writeTemp(t, "receipt.b64", r.Receipt)
	code, out, errb = deviceRun(t, "apple-receipt", "--receipt", rf, "--app-id", r.AppID, "--now", "2021-02-01T00:00:00Z")
	if code != 0 || !strings.Contains(out, `type: "ATTEST"`) {
		t.Fatalf("receipt: %d %q %q", code, out, errb)
	}
	code, out, _ = deviceRun(t, "apple-receipt", "--receipt", rf, "--now", "2022-01-01T00:00:00Z")
	if code != 1 || !strings.HasPrefix(out, "Refused: ") {
		t.Fatalf("expired receipt: %d %q", code, out)
	}
}

func TestDeviceAttestAndroidAndTPMUsage(t *testing.T) {
	if code, _, errb := deviceRun(t, "android", "--evidence", "x", "--nonce", "n"); code != 2 || !strings.Contains(errb, "--revocation") {
		t.Fatalf("android usage: %d %q", code, errb)
	}
	ev := writeTemp(t, "e.json", `["AAAA"]`)
	code, out, _ := deviceRun(t, "android", "--evidence", ev, "--nonce", "n", "--revocation", "off")
	if code != 1 || !strings.HasPrefix(out, "Refused: ") {
		t.Fatalf("android refusal: %d %q", code, out)
	}
	if code, _, errb := deviceRun(t, "tpm", "--evidence", ev, "--nonce", "n"); code != 2 || !strings.Contains(errb, "--root") {
		t.Fatalf("tpm usage: %d %q", code, errb)
	}
	if code, _, errb := deviceRun(t, "tpm-certify", "--evidence", ev, "--nonce", "n", "--allow-unverified-ek"); code != 2 || !strings.Contains(errb, "--activation-key") {
		t.Fatalf("tpm-certify usage: %d %q", code, errb)
	}
	if code, out, _ := deviceRun(t, "--help"); code != 0 || !strings.Contains(out, "tpm-certify") {
		t.Fatalf("help: %d", code)
	}
	var out2, err2 bytes.Buffer
	if code := run([]string{"device"}, &out2, &err2, zeros{}); code != 2 {
		t.Fatalf("device without subcommand: %d", code)
	}
}
