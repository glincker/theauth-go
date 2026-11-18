package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/iot/mqttauth"
)

// TestMQTTSQLStoreLookups checks the three device lookups return the same device, including its
// sorted certificate fingerprints, and that a device without certificates and unknown keys behave.
func TestMQTTSQLStoreLookups(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "mqtt.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	s := &mqttauth.SQLStore{DB: db}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	fpB := mqttauth.HashToken("b")
	fpA := mqttauth.HashToken("a")
	if fpA > fpB {
		fpA, fpB = fpB, fpA
	}
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	withCerts := mqttauth.Device{
		ID: "dev1", OrgID: "org1", Name: "n", Subject: "spiffe://x/dev1", Status: mqttauth.StatusActive, ExpiresAt: exp,
		CertFingerprints: []string{fpB, fpA}, TokenHashes: []string{mqttauth.HashToken("t")},
		Rules: []mqttauth.Rule{{Effect: mqttauth.Allow, Action: mqttauth.ActionAll, Filter: "a/#"}},
	}
	bare := mqttauth.Device{ID: "dev2", Status: mqttauth.StatusSuspended}
	for _, d := range []mqttauth.Device{withCerts, bare} {
		if err := s.PutDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	want := withCerts
	want.CertFingerprints = []string{fpA, fpB}
	for name, get := range map[string]func() (*mqttauth.Device, error){
		"id":      func() (*mqttauth.Device, error) { return s.DeviceByID(ctx, "dev1") },
		"subject": func() (*mqttauth.Device, error) { return s.DeviceBySubject(ctx, "spiffe://x/dev1") },
		"cert":    func() (*mqttauth.Device, error) { return s.DeviceByCertFingerprint(ctx, fpB) },
	} {
		got, err := get()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(*got, want) {
			t.Fatalf("%s: got %+v want %+v", name, *got, want)
		}
	}
	got, err := s.DeviceByID(ctx, "dev2")
	if err != nil || got.CertFingerprints != nil || got.Status != mqttauth.StatusSuspended {
		t.Fatalf("bare device: %+v %v", got, err)
	}
	for name, get := range map[string]func() (*mqttauth.Device, error){
		"id":            func() (*mqttauth.Device, error) { return s.DeviceByID(ctx, "nope") },
		"subject":       func() (*mqttauth.Device, error) { return s.DeviceBySubject(ctx, "nope") },
		"empty subject": func() (*mqttauth.Device, error) { return s.DeviceBySubject(ctx, "") },
		"cert":          func() (*mqttauth.Device, error) { return s.DeviceByCertFingerprint(ctx, mqttauth.HashToken("zzz")) },
	} {
		if _, err := get(); !errors.Is(err, mqttauth.ErrDeviceNotFound) {
			t.Fatalf("%s: want ErrDeviceNotFound, got %v", name, err)
		}
	}
}

// TestMQTTSQLStoreSubjectUsesIndex pins the plan of the subject lookup: it must search the partial
// unique index, not scan the table. Without the subject <> ” term SQLite scans.
func TestMQTTSQLStoreSubjectUsesIndex(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "plan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := (&mqttauth.SQLStore{DB: db}).EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := db.QueryContext(ctx, `EXPLAIN QUERY PLAN SELECT d.id FROM theauth_mqtt_devices d LEFT JOIN theauth_mqtt_device_certs c ON c.device_id = d.id WHERE d.subject = ? AND d.subject <> '' ORDER BY c.fingerprint`, "x")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	found := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		if detail == "SEARCH d USING INDEX theauth_mqtt_devices_subject (subject=?)" {
			found = true
		}
	}
	if !found {
		t.Fatal("subject lookup does not use theauth_mqtt_devices_subject")
	}
}
