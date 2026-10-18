package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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

func writeSuite(t *testing.T, expect string) string {
	t.Helper()
	doc := `{"policies":[{"version":"1","statements":[{"effect":"allow","actions":["read"],"resources":["docs/*"]}]}],` +
		`"cases":[{"name":"c","request":{"action":"read","resource":"docs/x"},"expect":"` + expect + `"}]}`
	path := filepath.Join(t.TempDir(), "suite.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
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
		{"policy no args", []string{"policy"}, 2, nil},
		{"policy missing file", []string{"policy", "test", "/nonexistent/suite.json"}, 2, nil},
		{"policy pass", []string{"policy", "test", writeSuite(t, "allowed")}, 0, func(t *testing.T, out string) {
			if !strings.Contains(out, "1 cases, 0 failed") {
				t.Fatalf("got %q", out)
			}
		}},
		{"policy fail", []string{"policy", "test", writeSuite(t, "denied")}, 1, nil},
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
