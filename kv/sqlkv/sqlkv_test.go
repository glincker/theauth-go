package sqlkv

import (
	"strings"
	"testing"
)

func TestRebindAndSchema(t *testing.T) {
	cases := []struct {
		name    string
		d       Dialect
		in      string
		want    string
		schema  string
		notWant string
	}{
		{"postgres numbers placeholders", Postgres, "a = ? AND b = ?", "a = $1 AND b = $2", "BYTEA", "VARCHAR"},
		{"mysql keeps question marks", MySQL, "a = ? AND b = ?", "a = ? AND b = ?", "VARCHAR(255)", "BYTEA"},
		{"sqlite keeps question marks", SQLite, "a = ?", "a = ?", "BLOB", "BYTEA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(nil, tc.d)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.q(tc.in); got != tc.want {
				t.Fatalf("q = %q want %q", got, tc.want)
			}
			ddl := Schema(tc.d, "theauth_kv")
			if !strings.Contains(ddl, tc.schema) || strings.Contains(ddl, tc.notWant) {
				t.Fatalf("schema: %s", ddl)
			}
		})
	}
}

func TestValidIdent(t *testing.T) {
	for in, want := range map[string]bool{"theauth_kv": true, "": false, "1a": false, "a-b": false, "a b": false, "A_1": true} {
		if validIdent(in) != want {
			t.Errorf("validIdent(%q) != %v", in, want)
		}
	}
}
