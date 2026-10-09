package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestRun(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		check    func(t *testing.T, out string)
	}{
		{"no args", nil, 2, nil},
		{"unknown", []string{"nope"}, 2, nil},
		{"secret base64url", []string{"secret"}, 0, func(t *testing.T, out string) {
			if strings.TrimSpace(out) != strings.Repeat("A", 43) {
				t.Fatalf("got %q", out)
			}
		}},
		{"secret hex", []string{"secret", "--format", "hex", "--bytes", "16"}, 0, func(t *testing.T, out string) {
			if strings.TrimSpace(out) != strings.Repeat("0", 32) {
				t.Fatalf("got %q", out)
			}
		}},
		{"secret env", []string{"secret", "--format", "env", "--name", "X"}, 0, func(t *testing.T, out string) {
			if !strings.HasPrefix(out, "X=") {
				t.Fatalf("got %q", out)
			}
		}},
		{"secret too short", []string{"secret", "--bytes", "8"}, 2, nil},
		{"secret bad format", []string{"secret", "--format", "pem"}, 2, nil},
		{"openapi", []string{"openapi", "--title", "T"}, 0, func(t *testing.T, out string) {
			var doc struct {
				OpenAPI string         `json:"openapi"`
				Paths   map[string]any `json:"paths"`
			}
			if err := json.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatal(err)
			}
			if doc.OpenAPI != "3.1.0" || doc.Paths["/auth/magic-link"] == nil {
				t.Fatalf("unexpected doc: %d paths", len(doc.Paths))
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run(tc.args, &out, &errb, zeros{})
			if code != tc.wantCode {
				t.Fatalf("code %d want %d, stderr=%s", code, tc.wantCode, errb.String())
			}
			if tc.check != nil {
				tc.check(t, out.String())
			}
		})
	}
}
