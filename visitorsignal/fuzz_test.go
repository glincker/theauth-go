package visitorsignal

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func FuzzValidatePayload(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("testdata", "payloads", "*.json"))
	for _, name := range files {
		b, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"v":1,"mode":"analytics","ts":1,"nonce":"abcdefghijklmnop","status":"suppressed",` +
		`"suppressedReason":"dnt","components":{"tz":"X"},"components":{},"flags":{"protectedBrowser":false,` +
		`"webdriver":false,"headlessHint":false,"inconsistent":false}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := ValidatePayload(raw)
		if err != nil {
			if CodeOf(err) == "" {
				t.Fatalf("untyped error: %v", err)
			}
			return
		}
		// Anything accepted must survive a round trip through the validator.
		again, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ValidatePayload(again); err != nil {
			t.Fatalf("accepted payload failed after re-encode: %v\n%s", err, again)
		}
	})
}

func FuzzCanonicalise(f *testing.F) {
	var vf vectorFile
	loadJSON(f, "vectors.json", &vf)
	for _, v := range vf.Vectors {
		b, err := json.Marshal(v.Components)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"tz":"<&>\u0000\"\\"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var c Components
		if json.Unmarshal(raw, &c) != nil {
			return
		}
		first, err := Canonicalise(c)
		if err != nil {
			return
		}
		var back Components
		if err := json.Unmarshal(first, &back); err != nil {
			t.Fatalf("canonical output is not JSON: %v\n%s", err, first)
		}
		second, err := Canonicalise(back)
		if err != nil || !bytes.Equal(first, second) {
			t.Fatalf("not idempotent:\n%s\n%s (%v)", first, second, err)
		}
	})
}
