package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeBackend struct {
	rows       []migrationRow
	migrateErr error
	migrated   bool
}

func (f *fakeBackend) Status(context.Context) ([]migrationRow, error) { return f.rows, nil }
func (f *fakeBackend) Close()                                         {}
func (f *fakeBackend) Migrate(context.Context) error {
	f.migrated = true
	return f.migrateErr
}

func useFake(t *testing.T, fb *fakeBackend) {
	t.Helper()
	old := openBackend
	openBackend = func(context.Context, string, string) (dbBackend, error) { return fb, nil }
	t.Cleanup(func() { openBackend = old })
}

func twoRows() []migrationRow {
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	return []migrationRow{
		newRow("0001_init", true, at, "CREATE TABLE a (id int);"),
		newRow("0002_passwords", false, time.Time{}, "CREATE TABLE b (id int);"),
	}
}

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb, zeros{})
	return code, out.String(), errb.String()
}

func TestDBStatus(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  []string
	}{
		{"text", []string{"--driver", "postgres", "--dsn", "x"}, 0,
			[]string{"0001", "init", "applied 2026-10-01T12:00:00Z", "0002", "pending", "1 applied, 1 pending"}},
		{"exit code on pending", []string{"--driver", "mysql", "--dsn", "x", "--exit-code"}, 1, []string{"1 pending"}},
		{"json", []string{"--driver", "postgres", "--dsn", "x", "--json"}, 0,
			[]string{`"driver": "postgres"`, `"applied": 1`, `"pending": 1`, `"id": "0002"`, `"name": "passwords"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFake(t, &fakeBackend{rows: twoRows()})
			code, out, _ := runCLI(append([]string{"db", "status"}, tt.args...)...)
			if code != tt.wantCode {
				t.Fatalf("code %d, want %d", code, tt.wantCode)
			}
			for _, w := range tt.wantOut {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q:\n%s", w, out)
				}
			}
		})
	}
}

func TestDBStatusJSONStable(t *testing.T) {
	useFake(t, &fakeBackend{rows: twoRows()})
	_, a, _ := runCLI("db", "status", "--driver", "postgres", "--dsn", "x", "--json")
	_, b, _ := runCLI("db", "status", "--driver", "postgres", "--dsn", "x", "--json")
	if a != b {
		t.Fatal("json output differs between runs")
	}
	var doc struct {
		Migrations []map[string]any `json:"migrations"`
	}
	if err := json.Unmarshal([]byte(a), &doc); err != nil || len(doc.Migrations) != 2 {
		t.Fatalf("bad json: %v\n%s", err, a)
	}
	if doc.Migrations[1]["applied_at"] != nil {
		t.Errorf("pending applied_at should be null: %v", doc.Migrations[1])
	}
}

func TestDBStatusAllApplied(t *testing.T) {
	rows := twoRows()
	rows[1] = newRow("0002_passwords", true, time.Now(), "")
	useFake(t, &fakeBackend{rows: rows})
	if code, _, _ := runCLI("db", "status", "--driver", "postgres", "--dsn", "x", "--exit-code"); code != 0 {
		t.Fatalf("code %d", code)
	}
}

func TestDBMigrate(t *testing.T) {
	t.Run("dry run prints sql and does not migrate", func(t *testing.T) {
		fb := &fakeBackend{rows: twoRows()}
		useFake(t, fb)
		code, out, _ := runCLI("db", "migrate", "--driver", "postgres", "--dsn", "x", "--dry-run")
		if code != 0 || fb.migrated {
			t.Fatalf("code %d migrated %v", code, fb.migrated)
		}
		if !strings.Contains(out, "CREATE TABLE b") || strings.Contains(out, "CREATE TABLE a") {
			t.Errorf("unexpected dry run output:\n%s", out)
		}
	})
	t.Run("applies pending", func(t *testing.T) {
		fb := &fakeBackend{rows: twoRows()}
		useFake(t, fb)
		code, out, _ := runCLI("db", "migrate", "--driver", "mysql", "--dsn", "x")
		if code != 0 || !fb.migrated || !strings.Contains(out, "applied 0002_passwords") {
			t.Fatalf("code %d migrated %v out %s", code, fb.migrated, out)
		}
	})
	t.Run("nothing pending", func(t *testing.T) {
		fb := &fakeBackend{rows: twoRows()[:1]}
		useFake(t, fb)
		code, out, _ := runCLI("db", "migrate", "--driver", "mysql", "--dsn", "x")
		if code != 0 || fb.migrated || !strings.Contains(out, "0 migrations applied") {
			t.Fatalf("code %d migrated %v out %s", code, fb.migrated, out)
		}
	})
	t.Run("migrate error is redacted", func(t *testing.T) {
		fb := &fakeBackend{rows: twoRows(), migrateErr: errors.New("boom hunter2")}
		useFake(t, fb)
		code, _, errOut := runCLI("db", "migrate", "--driver", "postgres", "--dsn", "postgres://u:hunter2@h/db")
		if code != 1 || strings.Contains(errOut, "hunter2") {
			t.Fatalf("code %d err %s", code, errOut)
		}
	})
}

func TestDBUsageErrors(t *testing.T) {
	t.Setenv(dsnEnv, "")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no subcommand", []string{"db"}, "usage"},
		{"no driver", []string{"db", "status", "--dsn", "x"}, "--driver is required"},
		{"bad driver", []string{"db", "status", "--driver", "oracle", "--dsn", "x"}, "unknown --driver"},
		{"sqlite library only", []string{"db", "status", "--driver", "sqlite", "--dsn", "x"}, "library only"},
		{"no dsn", []string{"db", "status", "--driver", "postgres"}, "no database"},
		{"to unsupported", []string{"db", "migrate", "--driver", "postgres", "--dsn", "x", "--to", "0002"}, "--to is not supported"},
		{"dry run on status", []string{"db", "status", "--driver", "postgres", "--dsn", "x", "--dry-run"}, "not valid"},
		{"unknown flag", []string{"db", "status", "--nope"}, "flag provided but not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := runCLI(tt.args...)
			if code != 2 || !strings.Contains(errOut, tt.want) {
				t.Fatalf("code %d err %q, want 2 containing %q", code, errOut, tt.want)
			}
		})
	}
}

func TestDBDSNFromEnv(t *testing.T) {
	t.Setenv(dsnEnv, "postgres://u:p@h/db")
	useFake(t, &fakeBackend{rows: twoRows()})
	if code, _, errOut := runCLI("db", "status", "--driver", "postgres"); code != 0 {
		t.Fatalf("code %d %s", code, errOut)
	}
}

func TestDBConnectErrorRedacted(t *testing.T) {
	old := openBackend
	defer func() { openBackend = old }()
	openBackend = func(_ context.Context, _, dsn string) (dbBackend, error) {
		return nil, errors.New("dial " + dsn + " failed")
	}
	code, _, errOut := runCLI("db", "status", "--driver", "mysql", "--dsn", "app:s3cret@tcp(h:3306)/db")
	if code != 1 || strings.Contains(errOut, "s3cret") || !strings.Contains(errOut, "xxxxx") {
		t.Fatalf("code %d err %q", code, errOut)
	}
}

func TestRedactDSN(t *testing.T) {
	tests := []struct{ in, want string }{
		{"postgres://u:hunter2@h:5432/db?sslmode=disable", "postgres://u:xxxxx@h:5432/db?sslmode=disable"},
		{"postgres://u@h/db", "postgres://u@h/db"},
		{"postgres://h/db?password=hunter2", "postgres://h/db?password=xxxxx"},
		{"host=h user=u password=hunter2 dbname=d", "host=h user=u password=xxxxx dbname=d"},
		{"app:hunter2@tcp(h:3306)/db?parseTime=true", "app:xxxxx@tcp(h:3306)/db?parseTime=true"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := redactDSN(tt.in)
			if got != tt.want || strings.Contains(got, "hunter2") {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

// TestDBRealBackendsUnreachable checks that the real openers fail cleanly (exit 1, no password).
func TestDBRealBackendsUnreachable(t *testing.T) {
	if os.Getenv("THEAUTH_TEST_PG_DSN") != "" {
		t.Skip("integration DSN present")
	}
	code, _, errOut := runCLI("db", "status", "--driver", "postgres", "--dsn", "postgres://u:hunter2@127.0.0.1:1/db?connect_timeout=1")
	if code != 1 || strings.Contains(errOut, "hunter2") {
		t.Fatalf("code %d err %q", code, errOut)
	}
}
