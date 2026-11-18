package visitorsignal

import (
	"encoding/json"
	"math"
	"testing"
)

type vectorFile struct {
	MasterSecretHex string `json:"masterSecretHex"`
	Vectors         []struct {
		Name       string     `json:"name"`
		SiteID     string     `json:"siteId"`
		Mode       Mode       `json:"mode"`
		Epoch      string     `json:"epoch"`
		Components Components `json:"components"`
		Canonical  string     `json:"canonical"`
		KeyHex     string     `json:"keyHex"`
		Hash       string     `json:"hash"`
	} `json:"vectors"`
}

func TestCanonicaliseVectors(t *testing.T) {
	t.Parallel()
	var vf vectorFile
	loadJSON(t, "vectors.json", &vf)
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			got, err := Canonicalise(v.Components)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != v.Canonical {
				t.Fatalf("got  %s\nwant %s", got, v.Canonical)
			}
		})
	}
}

func TestCanonicaliseCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   Components
		want string
		err  bool
	}{
		{"empty", Components{}, `{}`, false},
		{"html_not_escaped", Components{TZ: ptr(`<a>&"\`)}, `{"tz":"<a>&\"\\"}`, false},
		{"control_chars", Components{TZ: ptr("a\x00\x1f\n\t\b\f\r")}, `{"tz":"a\u0000\u001f\n\t\b\f\r"}`, false},
		{"unicode_raw", Components{TZ: ptr("é ")}, "{\"tz\":\"é \"}", false},
		{"memory_whole", Components{MemoryGB: ptr(8.0)}, `{"memoryGb":8}`, false},
		{"memory_quarter", Components{MemoryGB: ptr(0.25)}, `{"memoryGb":0.25}`, false},
		{"memory_half", Components{MemoryGB: ptr(0.5)}, `{"memoryGb":0.5}`, false},
		{"memory_zero", Components{MemoryGB: ptr(0.0)}, `{"memoryGb":0}`, false},
		{"memory_nan", Components{MemoryGB: ptr(math.NaN())}, "", true},
		{"memory_huge", Components{MemoryGB: ptr(1e21)}, "", true},
		{"negative_offset", Components{TZOffsetMin: ptr(-330)}, `{"tzOffsetMin":-330}`, false},
		{"bool_false_kept", Components{Mobile: ptr(false)}, `{"mobile":false}`, false},
		{"invalid_utf8", Components{TZ: ptr("\xff")}, "", true},
		{"prefix_key_order", Components{TZ: ptr("a"), TZOffsetMin: ptr(1)}, `{"tz":"a","tzOffsetMin":1}`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Canonicalise(tc.in)
			if (err != nil) != tc.err {
				t.Fatalf("err = %v, want error %v", err, tc.err)
			}
			if !tc.err && string(got) != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCanonicalOutputIsValidJSON(t *testing.T) {
	t.Parallel()
	got, err := Canonicalise(Components{TZ: ptr("a\x01\"")})
	if err != nil || !json.Valid(got) {
		t.Fatalf("invalid json %s (%v)", got, err)
	}
}
