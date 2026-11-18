package visitorsignal

import (
	"strings"
	"testing"
)

type extraFile struct {
	SignalV1 []struct {
		Name       string     `json:"name"`
		Pepper     string     `json:"pepper"`
		Components Components `json:"components"`
		Digest     string     `json:"digest"`
	} `json:"signalV1"`
	Sketch struct {
		Weights    map[string]float64 `json:"weights"`
		MinOverlap int                `json:"minOverlap"`
		Cases      []struct {
			Name       string            `json:"name"`
			A          map[string]string `json:"a"`
			B          map[string]string `json:"b"`
			Similarity float64           `json:"similarity"`
		} `json:"cases"`
		SketchOfBase map[string]string `json:"sketchOfBase"`
	} `json:"sketch"`
}

func TestSignalV1DigestVectors(t *testing.T) {
	t.Parallel()
	var ef extraFile
	loadJSON(t, "vectors-extra.json", &ef)
	for _, v := range ef.SignalV1 {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			got, err := ComputeSignalV1Digest(v.Components, v.Pepper)
			if err != nil || got != v.Digest {
				t.Fatalf("got %q, %v; want %q", got, err, v.Digest)
			}
		})
	}
}

const goodDigest = "dEdV9O2BP06ijkh6ZIf1dxyDzsWjuMUfp-N61hg7ZJI"

func sv1(digest, conf, comps, ts, extra string) []byte {
	return []byte(`{"v":1,"source":"browser","digest":"` + digest + `","confidence":` + conf +
		`,"components":` + comps + `,"ts":` + ts + extra + `}`)
}

func TestParseSignalV1(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  []byte
		want ErrorCode
	}{
		{"valid", sv1(goodDigest, "0.75", "9", "1763452800", ""), ""},
		{"confidence_zero", sv1(goodDigest, "0", "9", "1", ""), ""},
		{"confidence_one", sv1(goodDigest, "1", "9", "1", ""), ""},
		{"confidence_high", sv1(goodDigest, "1.01", "9", "1", ""), CodeSchemaInvalid},
		{"confidence_negative", sv1(goodDigest, "-0.1", "9", "1", ""), CodeSchemaInvalid},
		{"unknown_field", sv1(goodDigest, "0.5", "9", "1", `,"extra":1`), CodeSchemaInvalid},
		{"padded_digest", sv1(goodDigest+"=", "0.5", "9", "1", ""), CodeSchemaInvalid},
		{"short_digest", sv1(goodDigest[:40], "0.5", "9", "1", ""), CodeSchemaInvalid},
		{"std_alphabet_digest", sv1(strings.ReplaceAll(goodDigest, "-", "+"), "0.5", "9", "1", ""), CodeSchemaInvalid},
		{"components_too_many", sv1(goodDigest, "0.5", "18", "1", ""), CodeSchemaInvalid},
		{"components_negative", sv1(goodDigest, "0.5", "-1", "1", ""), CodeSchemaInvalid},
		{"negative_ts", sv1(goodDigest, "0.5", "9", "-1", ""), CodeSchemaInvalid},
		{"version_2", []byte(strings.Replace(string(sv1(goodDigest, "0.5", "9", "1", "")), `"v":1`, `"v":2`, 1)), CodeUnsupportedVersion},
		{"other_source", []byte(strings.Replace(string(sv1(goodDigest, "0.5", "9", "1", "")), "browser", "server", 1)), CodeSchemaInvalid},
		{"missing_ts", []byte(`{"v":1,"source":"browser","digest":"` + goodDigest + `","confidence":1,"components":1}`), CodeSchemaInvalid},
		{"over_512_bytes", sv1(goodDigest, "0.5", "9", "1", `,"x":"`+strings.Repeat("a", 512)+`"`), CodeSchemaInvalid},
		{"not_object", []byte(`[]`), CodeSchemaInvalid},
		{"wrong_case_key", []byte(strings.Replace(string(sv1(goodDigest, "0.5", "9", "1", "")), `"digest"`, `"Digest"`, 1)), CodeSchemaInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := ParseSignalV1(tc.raw)
			if got := CodeOf(err); got != tc.want {
				t.Fatalf("code = %q, want %q (%v)", got, tc.want, err)
			}
			if tc.want == "" && s.Digest != goodDigest {
				t.Fatalf("digest = %q", s.Digest)
			}
		})
	}
}

func TestParseSignalV1ExactlyAtCap(t *testing.T) {
	t.Parallel()
	base := sv1(goodDigest, "0.5", "9", "1", "")
	pad := SignalV1MaxBytes - len(base)
	raw := append(append([]byte{}, base[:len(base)-1]...), []byte(strings.Repeat(" ", pad))...)
	raw = append(raw, '}')
	if len(raw) != SignalV1MaxBytes {
		t.Fatalf("len = %d", len(raw))
	}
	if _, err := ParseSignalV1(raw); err != nil {
		t.Fatalf("512 bytes should parse: %v", err)
	}
}
