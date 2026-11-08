package mqttauth

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestSQLStorePostgres runs the lookup checks against THEAUTH_TEST_PG_DSN in a throwaway schema.
func TestSQLStorePostgres(t *testing.T) {
	dsn := os.Getenv("THEAUTH_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("THEAUTH_TEST_PG_DSN not set")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	const schema = "theauth_mqttauth_test"
	if _, err := admin.ExecContext(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.ExecContext(ctx, `DROP SCHEMA `+schema+` CASCADE`) }()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	s := &SQLStore{DB: db, Postgres: true}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	fpA, fpB := HashToken("a"), HashToken("b")
	if fpA > fpB {
		fpA, fpB = fpB, fpA
	}
	withCerts := Device{
		ID: "dev1", OrgID: "org1", Name: "n", Subject: "spiffe://x/dev1", Status: StatusActive,
		ExpiresAt: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), CertFingerprints: []string{fpB, fpA},
		TokenHashes: []string{HashToken("t")}, Rules: []Rule{{Effect: Allow, Action: ActionAll, Filter: "a/#"}},
	}
	for _, d := range []Device{withCerts, {ID: "dev2", Status: StatusSuspended}} {
		if err := s.PutDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	want := withCerts
	want.CertFingerprints = []string{fpA, fpB}
	for name, get := range map[string]func() (*Device, error){
		"id":      func() (*Device, error) { return s.DeviceByID(ctx, "dev1") },
		"subject": func() (*Device, error) { return s.DeviceBySubject(ctx, "spiffe://x/dev1") },
		"cert":    func() (*Device, error) { return s.DeviceByCertFingerprint(ctx, fpB) },
	} {
		got, err := get()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(*got, want) {
			t.Fatalf("%s: got %+v want %+v", name, *got, want)
		}
	}
	if d, err := s.DeviceByID(ctx, "dev2"); err != nil || d.CertFingerprints != nil {
		t.Fatalf("bare device: %+v %v", d, err)
	}
	for name, get := range map[string]func() (*Device, error){
		"id":      func() (*Device, error) { return s.DeviceByID(ctx, "nope") },
		"subject": func() (*Device, error) { return s.DeviceBySubject(ctx, "nope") },
		"empty":   func() (*Device, error) { return s.DeviceBySubject(ctx, "") },
		"cert":    func() (*Device, error) { return s.DeviceByCertFingerprint(ctx, HashToken("zzz")) },
	} {
		if _, err := get(); !errors.Is(err, ErrDeviceNotFound) {
			t.Fatalf("%s: want ErrDeviceNotFound, got %v", name, err)
		}
	}
}
