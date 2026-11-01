package mqttauth

import (
	"context"
	"errors"
	"testing"
)

// TestMemoryStoreIndexes covers the subject and fingerprint indexes: lookups, conflicts between
// devices, and the old keys of a replaced device becoming free again.
func TestMemoryStoreIndexes(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	fp1, fp2, fp3 := HashToken("c1"), HashToken("c2"), HashToken("c3")
	put := func(d Device) error { return m.PutDevice(ctx, d) }
	if err := put(Device{ID: "a", Status: StatusActive, Subject: "s-a", CertFingerprints: []string{fp1, fp2}}); err != nil {
		t.Fatal(err)
	}
	if err := put(Device{ID: "b", Status: StatusActive, Subject: "s-a"}); err == nil {
		t.Fatal("a second device with the same subject must conflict")
	}
	if err := put(Device{ID: "b", Status: StatusActive, CertFingerprints: []string{fp3, fp2}}); err == nil {
		t.Fatal("a second device with the same fingerprint must conflict")
	}
	if _, err := m.DeviceByCertFingerprint(ctx, fp3); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatal("a refused PutDevice must not leave index entries behind")
	}
	if err := put(Device{ID: "b", Status: StatusActive, Subject: "s-b", CertFingerprints: []string{fp3}}); err != nil {
		t.Fatal(err)
	}
	// Replacing a keeps its own keys usable and frees the dropped ones.
	if err := put(Device{ID: "a", Status: StatusActive, Subject: "s-a2", CertFingerprints: []string{fp1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DeviceBySubject(ctx, "s-a"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatal("old subject must be gone")
	}
	if _, err := m.DeviceByCertFingerprint(ctx, fp2); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatal("dropped fingerprint must be gone")
	}
	if d, err := m.DeviceBySubject(ctx, "s-a2"); err != nil || d.ID != "a" {
		t.Fatalf("new subject: %+v %v", d, err)
	}
	if d, err := m.DeviceByCertFingerprint(ctx, fp1); err != nil || d.ID != "a" {
		t.Fatalf("kept fingerprint: %+v %v", d, err)
	}
	// The freed keys can now belong to another device.
	if err := put(Device{ID: "c", Status: StatusActive, Subject: "s-a", CertFingerprints: []string{fp2}}); err != nil {
		t.Fatalf("freed keys must be reusable: %v", err)
	}
	if d, _ := m.DeviceBySubject(ctx, "s-a"); d == nil || d.ID != "c" {
		t.Fatalf("subject s-a: %+v", d)
	}
	// Returned devices are private copies.
	d, _ := m.DeviceByID(ctx, "a")
	d.CertFingerprints[0] = "mutated"
	if again, _ := m.DeviceByCertFingerprint(ctx, fp1); again == nil || again.ID != "a" {
		t.Fatal("mutating a returned device changed the store")
	}
	if ok, _ := m.SetStatus(ctx, "a", StatusRevoked); !ok {
		t.Fatal("SetStatus")
	}
	if d, _ := m.DeviceBySubject(ctx, "s-a2"); d == nil || d.Status != StatusRevoked {
		t.Fatalf("status not visible through the subject index: %+v", d)
	}
}
