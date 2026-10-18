package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/glincker/theauth-go/v2/iot/mqttauth"
	_ "modernc.org/sqlite"
)

func newStore(t *testing.T) *mqttauth.SQLStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	s := &mqttauth.SQLStore{DB: db}
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSQLStore(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("schema is not idempotent: %v", err)
	}
	fp := "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233"
	dev := mqttauth.Device{
		ID: "dev1", OrgID: "o1", Name: "boiler", Subject: "spiffe://x/dev1", Status: mqttauth.StatusActive,
		CertFingerprints: []string{fp}, TokenHashes: []string{mqttauth.HashToken("t")},
		Rules: []mqttauth.Rule{{Effect: mqttauth.Allow, Action: mqttauth.ActionPublish, Filter: "devices/{device_id}/#"}},
	}
	if err := s.PutDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	for name, get := range map[string]func() (*mqttauth.Device, error){
		"id":      func() (*mqttauth.Device, error) { return s.DeviceByID(ctx, "dev1") },
		"subject": func() (*mqttauth.Device, error) { return s.DeviceBySubject(ctx, "spiffe://x/dev1") },
		"cert":    func() (*mqttauth.Device, error) { return s.DeviceByCertFingerprint(ctx, fp) },
	} {
		got, err := get()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Name != "boiler" || got.OrgID != "o1" || len(got.Rules) != 1 || got.Rules[0] != dev.Rules[0] ||
			len(got.CertFingerprints) != 1 || len(got.TokenHashes) != 1 {
			t.Fatalf("%s: round trip mismatch %+v", name, got)
		}
	}
	if _, err := s.DeviceByID(ctx, "nope"); !errors.Is(err, mqttauth.ErrDeviceNotFound) {
		t.Fatalf("missing id: %v", err)
	}
	if _, err := s.DeviceBySubject(ctx, ""); !errors.Is(err, mqttauth.ErrDeviceNotFound) {
		t.Fatalf("empty subject: %v", err)
	}
	if _, err := s.DeviceByCertFingerprint(ctx, "00"); !errors.Is(err, mqttauth.ErrDeviceNotFound) {
		t.Fatalf("missing cert: %v", err)
	}
	if err := s.PutDevice(ctx, mqttauth.Device{ID: "dev2", Status: mqttauth.StatusActive, CertFingerprints: []string{fp}}); err == nil {
		t.Fatal("duplicate fingerprint accepted")
	}
	if err := s.PutDevice(ctx, mqttauth.Device{ID: "dev3", Status: mqttauth.StatusActive, Subject: "spiffe://x/dev1"}); err == nil {
		t.Fatal("duplicate subject accepted")
	}
	if _, err := s.DeviceByID(ctx, "dev2"); !errors.Is(err, mqttauth.ErrDeviceNotFound) {
		t.Fatal("failed insert left a device behind")
	}
	for _, id := range []string{"n1", "n2"} {
		if err := s.PutDevice(ctx, mqttauth.Device{ID: id, Status: mqttauth.StatusActive}); err != nil {
			t.Fatalf("devices without a subject must not collide: %v", err)
		}
	}
	dev.CertFingerprints, dev.Rules = nil, nil
	if err := s.PutDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeviceByCertFingerprint(ctx, fp); !errors.Is(err, mqttauth.ErrDeviceNotFound) {
		t.Fatal("old fingerprint still resolves after upsert")
	}
	if ok, err := s.SetStatus(ctx, "dev1", mqttauth.StatusRevoked); !ok || err != nil {
		t.Fatalf("revoke: %v %v", ok, err)
	}
	got, _ := s.DeviceByID(ctx, "dev1")
	if got.Status != mqttauth.StatusRevoked {
		t.Fatal("status not stored")
	}
	if ok, _ := s.SetStatus(ctx, "zzz", mqttauth.StatusRevoked); ok {
		t.Fatal("SetStatus on a missing device")
	}
	if _, err := s.SetStatus(ctx, "dev1", "bogus"); err == nil {
		t.Fatal("bogus status accepted")
	}
}

func TestSeededHandler(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := seed(ctx, s, "demo-token"); err != nil {
		t.Fatal(err)
	}
	h, err := mqttauth.New(mqttauth.Config{Store: s, BrokerSecret: "bs", CacheTTL: -1})
	if err != nil {
		t.Fatal(err)
	}
	call := func(path string, body map[string]any) string {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer bs")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out["result"].(string)
	}
	if got := call("/authn", map[string]any{"username": "demo-sensor", "password": "demo-token", "clientid": "demo-sensor"}); got != "allow" {
		t.Fatalf("authn: %s", got)
	}
	pub := map[string]any{"device_id": "demo-sensor", "action": "publish", "topic": "devices/demo-sensor/telemetry/temp"}
	if got := call("/authz", pub); got != "allow" {
		t.Fatalf("authz publish: %s", got)
	}
	pub["topic"] = "devices/other/telemetry/temp"
	if got := call("/authz", pub); got != "deny" {
		t.Fatalf("authz other device: %s", got)
	}
	if _, err := s.SetStatus(ctx, "demo-sensor", mqttauth.StatusRevoked); err != nil {
		t.Fatal(err)
	}
	pub["topic"] = "devices/demo-sensor/telemetry/temp"
	if got := call("/authz", pub); got != "deny" {
		t.Fatalf("revoked device: %s", got)
	}
}
