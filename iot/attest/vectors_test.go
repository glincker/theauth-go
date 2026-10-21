package attest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The vectors in testdata/vectors.json were produced by running the TypeScript verifiers
// (sdk/packages/core/src/device/attestation) over the real vendor fixtures next to them, and
// by tampering with those fixtures. Every vector must produce the same ok flag, the same refusal
// reason and the same claims here.

type vectorFile struct {
	Vectors []vector `json:"vectors"`
}

type vector struct {
	Verifier     string         `json:"verifier"`
	Name         string         `json:"name"`
	Options      map[string]any `json:"options"`
	Input        vectorInput    `json:"input"`
	EvidenceRef  map[string]any `json:"evidenceRef"`
	Expect       *vectorExpect  `json:"expect"`
	Throws       string         `json:"throws"`
	SeenSerials  []string       `json:"seenSerials"`
	NoteIgnored  string         `json:"note"`
	ThumbprintOf string         `json:"thumbprintOf"`
}

type vectorInput struct {
	Evidence                string `json:"evidence"`
	Nonce                   string `json:"nonce"`
	CredentialKind          string `json:"credentialKind"`
	CredentialKeyThumbprint string `json:"credentialKeyThumbprint"`
	EnrollmentID            string `json:"enrollmentId"`
}

type vectorExpect struct {
	OK     bool           `json:"ok"`
	Reason string         `json:"reason"`
	Claims map[string]any `json:"claims"`
}

func readJSON(t testing.TB, path string, into any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

type fixtures struct {
	android struct {
		Chains map[string][]string `json:"chains"`
	}
	apple struct {
		Fixtures map[string]struct {
			Attestation string `json:"attestation"`
			KeyID       string `json:"keyId"`
		} `json:"fixtures"`
	}
	tpm struct {
		RootCertificate string               `json:"rootCertificate"`
		AkPublic        string               `json:"akPublic"`
		AkCertificates  []string             `json:"akCertificates"`
		WithNonce       map[string]tpmSample `json:"withNonce"`
		WithoutNonce    map[string]tpmSample `json:"withoutNonce"`
	}
}

type tpmSample struct {
	Quote     string                       `json:"quote"`
	Signature string                       `json:"signature"`
	Pcrs      map[string]map[string]string `json:"pcrs"`
}

func loadFixtures(t testing.TB) *fixtures {
	f := &fixtures{}
	readJSON(t, "testdata/android-key-attestation.json", &f.android)
	readJSON(t, "testdata/apple-app-attest.json", &f.apple)
	readJSON(t, "testdata/tpm2-quote-gce.json", &f.tpm)
	return f
}

func (f *fixtures) evidence(t *testing.T, v vector) string {
	t.Helper()
	ref := v.EvidenceRef
	if ref == nil {
		return v.Input.Evidence
	}
	switch v.Verifier {
	case "android":
		chain := f.android.Chains[ref["chain"].(string)]
		var out []string
		if order, ok := ref["order"].([]any); ok {
			for _, i := range order {
				out = append(out, chain[int(i.(float64))])
			}
		} else {
			drop := map[int]bool{}
			for _, i := range ref["drop"].([]any) {
				drop[int(i.(float64))] = true
			}
			for i, c := range chain {
				if !drop[i] {
					out = append(out, c)
				}
			}
		}
		b, _ := json.Marshal(out)
		return string(b)
	case "apple":
		fx := f.apple.Fixtures[ref["fixture"].(string)]
		b, _ := json.Marshal(map[string]string{"attestation": fx.Attestation, "keyId": fx.KeyID})
		return string(b)
	default:
		samples := f.tpm.WithNonce
		if ref["group"] == "withoutNonce" {
			samples = f.tpm.WithoutNonce
		}
		s := samples[ref["bank"].(string)]
		b, _ := json.Marshal(map[string]any{
			"akPublic": f.tpm.AkPublic, "akCertificates": f.tpm.AkCertificates,
			"quote": s.Quote, "signature": s.Signature, "pcrs": s.Pcrs,
		})
		return string(b)
	}
}

func (f *fixtures) roots(t *testing.T, o map[string]any) []string {
	t.Helper()
	ref, _ := o["rootsRef"].(string)
	switch {
	case ref == "google":
		return GoogleAttestationRoots
	case ref == "apple":
		return AppleAppAttestRoots
	case ref == "tpmRoot":
		return []string{f.tpm.RootCertificate}
	case strings.HasPrefix(ref, "chain3:"):
		return []string{f.android.Chains[strings.TrimPrefix(ref, "chain3:")][3]}
	}
	return nil
}

func strList(v any) []string {
	out := []string{}
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func optTime(t *testing.T, o map[string]any) func() time.Time {
	ts, err := time.Parse(time.RFC3339, o["now"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return func() time.Time { return ts }
}

func optBool(o map[string]any, key string) *bool {
	if v, ok := o[key].(bool); ok {
		return Bool(v)
	}
	return nil
}

func optString(o map[string]any, key string) string {
	s, _ := o[key].(string)
	return s
}

func buildVerifier(t *testing.T, f *fixtures, v vector, seen *[]string) (Verifier, error) {
	o := v.Options
	switch v.Verifier {
	case "android":
		if o["constructWithoutRevocation"] == true {
			return NewAndroidKeyVerifier(AndroidKeyOptions{})
		}
		opts := AndroidKeyOptions{
			Roots: f.roots(t, o), MinSecurityLevel: optString(o, "minSecurityLevel"),
			BootPolicy: optString(o, "bootPolicy"), BindKey: optBool(o, "bindKey"),
			ChallengeEncoding: ChallengeEncoding(optString(o, "challengeEncoding")), Now: optTime(t, o),
		}
		if list, ok := o["allowedPackages"]; ok {
			opts.AllowedPackages = strList(list)
		}
		if s, ok := o["revocation"].(string); ok && s == "disabled" {
			opts.RevocationDisabled = true
		} else if rv, ok := o["revocation"].(map[string]any); ok {
			revoked := map[string]bool{}
			for _, s := range strList(rv["revoked"]) {
				revoked[s] = true
			}
			opts.Revocation = func(_ context.Context, serial string) (bool, error) {
				*seen = append(*seen, serial)
				return revoked[serial], nil
			}
		}
		return NewAndroidKeyVerifier(opts)
	case "apple":
		opts := AppleAppAttestOptions{
			Roots: f.roots(t, o), Environment: optString(o, "environment"), Bind: optString(o, "bind"),
			ClientDataHash: optString(o, "clientDataHash"), ChallengeEncoding: ChallengeEncoding(optString(o, "challengeEncoding")),
			Now: optTime(t, o),
		}
		if ids, ok := o["appIds"]; ok {
			opts.AppIDs = strList(ids)
		}
		if cats, ok := o["allowedValidationCategories"].([]any); ok {
			opts.AllowedValidationCategories = []int64{}
			for _, c := range cats {
				opts.AllowedValidationCategories = append(opts.AllowedValidationCategories, int64(c.(float64)))
			}
		}
		return NewAppleAppAttestVerifier(opts)
	default:
		if o["constructWithoutRoots"] == true {
			return NewTPM2QuoteVerifier(TPM2Options{})
		}
		opts := TPM2Options{
			Roots: f.roots(t, o), AllowUnverifiedAk: o["allowUnverifiedAk"] == true,
			ChallengeEncoding: ChallengeEncoding(optString(o, "challengeEncoding")),
			RequireSafeClock:  optBool(o, "requireSafeClock"), Now: optTime(t, o),
		}
		if exp, ok := o["expectedPcrs"].(map[string]any); ok {
			opts.ExpectedPCRs = map[string]map[int]string{}
			for bank, m := range exp {
				opts.ExpectedPCRs[bank] = map[int]string{}
				for idx, hx := range m.(map[string]any) {
					n := 0
					for _, c := range idx {
						n = n*10 + int(c-'0')
					}
					opts.ExpectedPCRs[bank][n] = hx.(string)
				}
			}
		}
		return NewTPM2QuoteVerifier(opts)
	}
}

func roundTrip(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSharedVectorsMatchTypeScript(t *testing.T) {
	var file vectorFile
	readJSON(t, "testdata/vectors.json", &file)
	f := loadFixtures(t)
	if len(file.Vectors) < 100 {
		t.Fatalf("expected at least 100 vectors, got %d", len(file.Vectors))
	}
	counts := map[string]int{}
	for _, v := range file.Vectors {
		counts[v.Verifier]++
		t.Run(v.Verifier+"/"+v.Name, func(t *testing.T) {
			var seen []string
			verify, err := buildVerifier(t, f, v, &seen)
			if v.Throws != "" {
				if err == nil {
					t.Fatalf("TypeScript refused at construction (%s), Go built a verifier", v.Throws)
				}
				return
			}
			if err != nil {
				t.Fatalf("construct: %v", err)
			}
			in := Input{
				Evidence: f.evidence(t, v), Nonce: v.Input.Nonce, EnrollmentID: "e1",
				CredentialKind: v.Input.CredentialKind, CredentialKeyThumbprint: v.Input.CredentialKeyThumbprint,
			}
			res, err := verify(context.Background(), in)
			if err != nil {
				t.Fatalf("verify returned an error: %v", err)
			}
			want := v.Expect
			if res.OK != want.OK {
				t.Fatalf("ok = %v (%s), TypeScript ok = %v (%s)", res.OK, res.Reason, want.OK, want.Reason)
			}
			reason := want.Reason
			if v.Name == "empty nonce" {
				// TypeScript treats "" as a present nonce and refuses it later. Go refuses it up front.
				reason = "TPM quote needs the enrollment nonce"
			}
			if res.Reason != reason {
				t.Fatalf("reason = %q, TypeScript reason = %q", res.Reason, reason)
			}
			if want.OK && !reflect.DeepEqual(roundTrip(t, res.Claims), want.Claims) {
				t.Fatalf("claims differ\n go: %v\n ts: %v", roundTrip(t, res.Claims), want.Claims)
			}
			if v.SeenSerials != nil && !reflect.DeepEqual(seen, v.SeenSerials) {
				t.Fatalf("revocation lookups = %v, want %v", seen, v.SeenSerials)
			}
		})
	}
	for _, name := range []string{"android", "apple", "tpm"} {
		if counts[name] < 20 {
			t.Errorf("only %d %s vectors", counts[name], name)
		}
	}
}

func TestBase64Helper(t *testing.T) {
	got, err := decodeBase64("-_8")
	if err != nil || base64.StdEncoding.EncodeToString(got) != "+/8=" {
		t.Fatalf("got %v %v", got, err)
	}
	if _, err := decodeBase64("A"); err == nil {
		t.Fatal("length 1 mod 4 must fail")
	}
}
