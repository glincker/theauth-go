package mqttauth

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// benchSQLStore measures the SQL device lookups against any database/sql handle. The SQLite
// twin lives in storage/sqlite (the root module has no SQLite driver).
func benchSQLStore(b *testing.B, db *sql.DB, postgres bool, devices int) {
	b.Helper()
	ctx := context.Background()
	s := &SQLStore{DB: db, Postgres: postgres}
	if err := s.EnsureSchema(ctx); err != nil {
		b.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM theauth_mqtt_device_certs`); err != nil {
		b.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM theauth_mqtt_devices`); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < devices; i++ {
		d := *benchDevice()
		d.ID = "dev" + strconv.Itoa(i)
		d.Subject = "spiffe://example.org/" + d.ID
		d.CertFingerprints = []string{HashToken("cert-" + d.ID)}
		d.TokenHashes = []string{HashToken("tok-" + d.ID)}
		if err := s.PutDevice(ctx, d); err != nil {
			b.Fatal(err)
		}
	}
	mid := devices / 2
	b.Run("DeviceByID", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := s.DeviceByID(ctx, "dev"+strconv.Itoa(mid)); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("DeviceBySubject", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := s.DeviceBySubject(ctx, "spiffe://example.org/dev"+strconv.Itoa(mid)); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("DeviceByCertFingerprint", func(b *testing.B) {
		fp := HashToken("cert-dev" + strconv.Itoa(mid))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := s.DeviceByCertFingerprint(ctx, fp); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("AuthorizeUncached", func(b *testing.B) {
		h, err := New(Config{Store: s, BrokerSecret: "broker-secret-0123456789", CacheTTL: -1, AllowSampleRate: -1})
		if err != nil {
			b.Fatal(err)
		}
		id := "dev" + strconv.Itoa(mid)
		req := brokerRequest{Username: id, ClientID: id}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if d, _, _ := h.authorize(ctx, req, ActionPublish, fmt.Sprintf("devices/%s/telemetry/t", id)); !d.Allowed {
				b.Fatal("want allow")
			}
		}
	})
}

// BenchmarkSQLStorePostgres runs the SQL store benchmarks against THEAUTH_TEST_PG_DSN. The tables
// are created if missing and their rows are replaced, so use a scratch database.
func BenchmarkSQLStorePostgres(b *testing.B) {
	dsn := os.Getenv("THEAUTH_TEST_PG_DSN")
	if dsn == "" {
		b.Skip("THEAUTH_TEST_PG_DSN not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	benchSQLStore(b, db, true, 10000)
}
