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

func TestDefaultPrefixApplied(t *testing.T) {
	cases := []struct {
		name    string
		opts    []Option
		wantKey string
	}{
		{"no option uses the default", nil, "theauth:k"},
		{"custom prefix", []Option{WithPrefix("app1:")}, "app1:k"},
		{"WithoutPrefix disables the prefix", []Option{WithoutPrefix()}, "k"},
		{"explicit empty prefix disables the prefix", []Option{WithPrefix("")}, "k"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(nil, SQLite, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.key("k"); got != tc.wantKey {
				t.Fatalf("key = %q want %q", got, tc.wantKey)
			}
		})
	}
}

func TestScopePredicate(t *testing.T) {
	cases := []struct {
		name     string
		d        Dialect
		opts     []Option
		wantSQL  string
		wantArgs []any
	}{
		{"postgres counts characters", Postgres, nil, " AND substr(k, 1, ?) = ?", []any{8, "theauth:"}},
		{"sqlite counts characters", SQLite, nil, " AND substr(k, 1, ?) = ?", []any{8, "theauth:"}},
		{"mysql compares bytes in binary", MySQL, nil, " AND LEFT(BINARY k, ?) = ?", []any{8, "theauth:"}},
		{"multibyte prefix in characters", SQLite, []Option{WithPrefix("é:")}, " AND substr(k, 1, ?) = ?", []any{2, "é:"}},
		{"multibyte prefix in bytes on mysql", MySQL, []Option{WithPrefix("é:")}, " AND LEFT(BINARY k, ?) = ?", []any{3, "é:"}},
		{"opt-out has no predicate", SQLite, []Option{WithoutPrefix()}, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(nil, tc.d, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			gotSQL, gotArgs := s.scope()
			if gotSQL != tc.wantSQL {
				t.Fatalf("scope = %q want %q", gotSQL, tc.wantSQL)
			}
			if len(gotArgs) != len(tc.wantArgs) {
				t.Fatalf("args = %v want %v", gotArgs, tc.wantArgs)
			}
			for i := range gotArgs {
				if gotArgs[i] != tc.wantArgs[i] {
					t.Fatalf("args = %v want %v", gotArgs, tc.wantArgs)
				}
			}
		})
	}
}

func TestScopePredicateRebindsForPostgres(t *testing.T) {
	s, err := New(nil, Postgres)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := s.scope()
	got := s.q("DELETE FROM theauth_kv WHERE expires_at <= ?" + scope)
	want := "DELETE FROM theauth_kv WHERE expires_at <= $1 AND substr(k, 1, $2) = $3"
	if got != want {
		t.Fatalf("q = %q want %q", got, want)
	}
}

func TestValidIdent(t *testing.T) {
	for in, want := range map[string]bool{"theauth_kv": true, "": false, "1a": false, "a-b": false, "a b": false, "A_1": true} {
		if validIdent(in) != want {
			t.Errorf("validIdent(%q) != %v", in, want)
		}
	}
}

func TestNewRejectsHostileTableName(t *testing.T) {
	for _, name := range []string{"", "t; DROP TABLE users", "a b", "a-b", "1abc", "t\"x", "t`x", "t'--", "a.b", strings.Repeat("a", 64)} {
		if _, err := New(nil, SQLite, WithTable(name)); err == nil {
			t.Errorf("table %q accepted, want error", name)
		}
	}
	if _, err := New(nil, SQLite, WithTable("ok_Table1")); err != nil {
		t.Errorf("valid table rejected: %v", err)
	}
}
