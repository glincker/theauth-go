package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/glincker/theauth-go/v2/iot/mqttauth"
)

// BenchmarkMQTTSQLStore measures the device lookups the MQTT broker hook makes on a cache miss,
// against SQLite with 10000 devices. The Postgres twin is BenchmarkSQLStorePostgres in
// iot/mqttauth.
func BenchmarkMQTTSQLStore(b *testing.B) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(b.TempDir(), "mqtt.db")+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	s := &mqttauth.SQLStore{DB: db}
	if err := s.EnsureSchema(ctx); err != nil {
		b.Fatal(err)
	}
	const devices = 10000
	for i := 0; i < devices; i++ {
		id := "dev" + strconv.Itoa(i)
		d := mqttauth.Device{
			ID: id, OrgID: "org9", Status: mqttauth.StatusActive, Subject: "spiffe://example.org/" + id,
			CertFingerprints: []string{mqttauth.HashToken("cert-" + id)},
			TokenHashes:      []string{mqttauth.HashToken("tok-" + id)},
			Rules:            []mqttauth.Rule{{Effect: mqttauth.Allow, Action: mqttauth.ActionPublish, Filter: "devices/{device_id}/telemetry/#"}},
		}
		if err := s.PutDevice(ctx, d); err != nil {
			b.Fatal(err)
		}
	}
	mid := "dev" + strconv.Itoa(devices/2)
	b.Run("DeviceByID", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := s.DeviceByID(ctx, mid); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("DeviceBySubject", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := s.DeviceBySubject(ctx, "spiffe://example.org/"+mid); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("DeviceByCertFingerprint", func(b *testing.B) {
		fp := mqttauth.HashToken("cert-" + mid)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := s.DeviceByCertFingerprint(ctx, fp); err != nil {
				b.Fatal(err)
			}
		}
	})
}
