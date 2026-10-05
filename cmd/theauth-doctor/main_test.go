package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glincker/theauth-go"
)

func fakeServer(t *testing.T, rep theauth.Report) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(rep)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestRun(t *testing.T) {
	rep := theauth.Report{
		Summary:  map[theauth.Severity]int{theauth.SeverityMedium: 1},
		Findings: []theauth.Finding{{ID: "x.y", Severity: theauth.SeverityMedium, Title: "Thing"}},
	}
	srv := fakeServer(t, rep)
	good := env(map[string]string{tokenEnv: "tok"})
	cases := []struct {
		name    string
		args    []string
		env     func(string) string
		tty     bool
		code    int
		contain string
		absent  string
	}{
		{"table no color", []string{"--server", srv.URL}, good, false, 0, "MEDIUM", "\x1b["},
		{"table color on tty", []string{"--server", srv.URL}, good, true, 0, "\x1b[33m", ""},
		{"no-color flag", []string{"--server", srv.URL, "--no-color"}, good, true, 0, "MEDIUM", "\x1b["},
		{"json", []string{"--server", srv.URL, "--format", "json"}, good, true, 0, `"id": "x.y"`, "\x1b["},
		{"fail-on met", []string{"--server", srv.URL, "--fail-on", "medium"}, good, false, 1, "x.y", ""},
		{"fail-on not met", []string{"--server", srv.URL, "--fail-on", "high"}, good, false, 0, "x.y", ""},
		{"bad token", []string{"--server", srv.URL}, env(map[string]string{tokenEnv: "bad"}), false, 1, "", ""},
		{"missing token", []string{"--server", srv.URL}, env(nil), false, 2, "", ""},
		{"missing server", nil, good, false, 2, "", ""},
		{"bad severity", []string{"--server", srv.URL, "--fail-on", "nope"}, good, false, 2, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run(tc.args, &out, &errb, tc.env, tc.tty)
			if code != tc.code {
				t.Fatalf("exit %d, want %d (stderr %q)", code, tc.code, errb.String())
			}
			if tc.contain != "" && !strings.Contains(out.String(), tc.contain) {
				t.Fatalf("stdout %q lacks %q", out.String(), tc.contain)
			}
			if tc.absent != "" && strings.Contains(out.String(), tc.absent) {
				t.Fatalf("stdout %q contains %q", out.String(), tc.absent)
			}
		})
	}
}
