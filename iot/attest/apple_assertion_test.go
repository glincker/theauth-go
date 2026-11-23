package attest

import (
	"encoding/json"
	"testing"
	"time"
)

// testdata/apple-assertion-receipt-vectors.json is produced by the TypeScript verifiers over the real
// recordings in testdata/apple-app-assertion.json (veehaitch/devicecheck-appattest and block/buzz,
// both Apache-2.0, see README.md) and tampered variants. Each case must give the same verdict and
// the same refusal sentence here.

type assertionVectors struct {
	Assertions []struct {
		Name  string `json:"name"`
		Input struct {
			Assertion       string  `json:"assertion"`
			ClientData      string  `json:"clientData"`
			AppID           string  `json:"appId"`
			PublicKey       string  `json:"publicKey"`
			PreviousCounter float64 `json:"previousCounter"`
		} `json:"input"`
		Expect struct {
			OK      bool   `json:"ok"`
			Reason  string `json:"reason"`
			Counter uint32 `json:"counter"`
			Flags   byte   `json:"flags"`
		} `json:"expect"`
	} `json:"assertions"`
	Receipts []struct {
		Name    string `json:"name"`
		Receipt string `json:"receipt"`
		Options struct {
			AppID     string   `json:"appId"`
			PublicKey string   `json:"publicKey"`
			Roots     []string `json:"roots"`
		} `json:"options"`
		Now    string `json:"now"`
		Expect struct {
			OK      bool   `json:"ok"`
			Reason  string `json:"reason"`
			Receipt struct {
				AppID                 string   `json:"appId"`
				Type                  string   `json:"type"`
				Environment           *string  `json:"environment"`
				CreationTime          string   `json:"creationTime"`
				NotBefore             *string  `json:"notBefore"`
				ExpirationTime        *string  `json:"expirationTime"`
				RiskMetric            *float64 `json:"riskMetric"`
				Token                 string   `json:"token"`
				AttestedKeyThumbprint *string  `json:"attestedKeyThumbprint"`
			} `json:"receipt"`
		} `json:"expect"`
	} `json:"receipts"`
}

func loadAssertionVectors(t *testing.T) assertionVectors {
	t.Helper()
	var v assertionVectors
	readJSON(t, "testdata/apple-assertion-receipt-vectors.json", &v)
	return v
}

func TestAppleAssertionMatchesTypeScript(t *testing.T) {
	v := loadAssertionVectors(t)
	if len(v.Assertions) < 30 {
		t.Fatalf("only %d cases", len(v.Assertions))
	}
	okCount := 0
	for _, c := range v.Assertions {
		t.Run(c.Name, func(t *testing.T) {
			got := VerifyAppleAssertion(AppleAssertionInput{
				Assertion: c.Input.Assertion, ClientData: []byte(c.Input.ClientData), AppID: c.Input.AppID,
				PublicKey: c.Input.PublicKey, PreviousCounter: int64(c.Input.PreviousCounter),
			})
			if got.OK != c.Expect.OK || got.Reason != c.Expect.Reason {
				t.Fatalf("got %v, TS says ok=%v reason=%q", got, c.Expect.OK, c.Expect.Reason)
			}
			if got.OK {
				okCount++
				if got.Counter != c.Expect.Counter || got.Flags != c.Expect.Flags {
					t.Fatalf("counter/flags %d/%d, TS says %d/%d", got.Counter, got.Flags, c.Expect.Counter, c.Expect.Flags)
				}
			}
		})
	}
	if okCount < 4 {
		t.Fatalf("expected the real recordings to verify, got %d ok", okCount)
	}
}

func TestAppleReceiptMatchesTypeScript(t *testing.T) {
	v := loadAssertionVectors(t)
	if len(v.Receipts) < 30 {
		t.Fatalf("only %d cases", len(v.Receipts))
	}
	okCount := 0
	for _, c := range v.Receipts {
		t.Run(c.Name, func(t *testing.T) {
			now, err := time.Parse(time.RFC3339, c.Now)
			if err != nil {
				t.Fatal(err)
			}
			got := VerifyAppleReceipt(c.Receipt, AppleReceiptOptions{
				AppID: c.Options.AppID, PublicKey: c.Options.PublicKey, Roots: c.Options.Roots,
				Now: func() time.Time { return now },
			})
			if got.OK != c.Expect.OK || got.Reason != c.Expect.Reason {
				t.Fatalf("got ok=%v reason=%q, TS says ok=%v reason=%q", got.OK, got.Reason, c.Expect.OK, c.Expect.Reason)
			}
			if !got.OK {
				return
			}
			okCount++
			r, e := got.Receipt, c.Expect.Receipt
			iso := func(tm *time.Time) *string {
				if tm == nil {
					return nil
				}
				s := tm.UTC().Format("2006-01-02T15:04:05.000Z")
				return &s
			}
			same := func(a, b *string) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }
			env := &r.Environment
			if r.Environment == "" {
				env = nil
			}
			thumb := &r.AttestedKeyThumbprint
			if r.AttestedKeyThumbprint == "" {
				thumb = nil
			}
			var metric *float64
			if r.RiskMetric != nil {
				f := float64(*r.RiskMetric)
				metric = &f
			}
			if r.AppID != e.AppID || r.Type != e.Type || r.Token != e.Token ||
				!same(env, e.Environment) || !same(iso(&r.CreationTime), &e.CreationTime) ||
				!same(iso(r.NotBefore), e.NotBefore) || !same(iso(r.ExpirationTime), e.ExpirationTime) ||
				!same(thumb, e.AttestedKeyThumbprint) || (metric == nil) != (e.RiskMetric == nil) ||
				(metric != nil && *metric != *e.RiskMetric) {
				b, _ := json.Marshal(r)
				t.Fatalf("receipt %s differs from TS %+v", b, e)
			}
		})
	}
	if okCount < 5 {
		t.Fatalf("expected the real receipts to verify, got %d ok", okCount)
	}
}

func TestBerToDER(t *testing.T) {
	in := []byte{0x30, 0x80, 0x24, 0x80, 0x04, 0x02, 0x61, 0x62, 0x04, 0x02, 0x63, 0x64, 0, 0, 0, 0}
	out, err := berToDER(in)
	want := []byte{0x30, 0x06, 0x04, 0x04, 0x61, 0x62, 0x63, 0x64}
	if err != nil || string(out) != string(want) {
		t.Fatalf("got %x %v", out, err)
	}
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	if out, err := berToDER(der); err != nil || string(out) != string(der) {
		t.Fatalf("der changed: %x %v", out, err)
	}
	for _, bad := range [][]byte{{0x30, 0x80, 0x02, 0x01, 0x05}, {0x04, 0x80, 0x01}, {0x30, 0x05, 0x02}} {
		if _, err := berToDER(bad); err == nil {
			t.Fatalf("%x accepted", bad)
		}
	}
}

// The receipt and assertion parsers read bytes an attacker controls. Whatever they are given, they must
// answer with a refusal and never panic.
func FuzzAppleReceiptAndAssertion(f *testing.F) {
	v := func() assertionVectors {
		var v assertionVectors
		readJSON(f, "testdata/apple-assertion-receipt-vectors.json", &v)
		return v
	}()
	for _, c := range v.Receipts[:3] {
		f.Add(c.Receipt)
	}
	for _, c := range v.Assertions[:2] {
		f.Add(c.Input.Assertion)
	}
	f.Add("MIAGCSqGSIb3DQEHAqCAMIAGCSqGSIb3DQEHAaCAJIAEAAAAAAAA")
	f.Fuzz(func(t *testing.T, s string) {
		_ = VerifyAppleReceipt(s, AppleReceiptOptions{})
		_ = VerifyAppleAssertion(AppleAssertionInput{Assertion: s, ClientData: []byte("x"), AppID: "T.b", PublicKey: v.Assertions[0].Input.PublicKey})
		_, _ = berToDER([]byte(s))
	})
}

func FuzzMakeCredentialInput(f *testing.F) {
	var fx tpmFixture
	readJSON(f, "testdata/tpm2-swtpm.json", &fx)
	ek, _ := decodeBase64(fx.RSA.EKPublic)
	f.Add(ek, []byte("name"), []byte("secret"))
	f.Fuzz(func(t *testing.T, ek, name, credential []byte) {
		_, _ = MakeCredential(ek, name, credential, nil)
	})
}
