package mqttauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/policy"
)

// ErrDeviceNotFound is returned by a DeviceStore when no device matches.
var ErrDeviceNotFound = errors.New("mqttauth: device not found")

// Device statuses. Only StatusActive devices may connect.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusRevoked   = "revoked"
)

// Effect is the outcome of an ACL rule.
type Effect string

// Rule effects. A matching deny always wins over any allow.
const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

// Action is an MQTT operation a rule applies to.
type Action string

// Rule actions. ActionAll covers publish and subscribe.
const (
	ActionPublish   Action = "publish"
	ActionSubscribe Action = "subscribe"
	ActionAll       Action = "all"
)

// Rule grants or denies one action on a topic filter. The filter may contain the MQTT wildcards
// and the placeholders {device_id} and {org_id}, replaced with the authenticated device's values
// before matching (for example "devices/{device_id}/telemetry").
type Rule struct {
	Effect Effect `json:"effect"`
	Action Action `json:"action"`
	Filter string `json:"filter"`
}

// Device is the broker-facing view of a device principal. The field names match the device
// registry of the TypeScript SDK where the concept is shared: id, orgId, name, status and subject.
type Device struct {
	ID    string `json:"id"`
	OrgID string `json:"orgId,omitempty"`
	Name  string `json:"name,omitempty"`
	// Subject is the access token subject for the JWT path, usually the SPIFFE ID. Empty means
	// the token subject is the device ID.
	Subject string `json:"subject,omitempty"`
	Status  string `json:"status"`
	// CertFingerprints are lowercase hex SHA-256 digests of the DER client certificates the
	// device may present (see NormalizeFingerprint).
	CertFingerprints []string `json:"certFingerprints,omitempty"`
	// TokenHashes are HashToken digests of the opaque device tokens accepted as the MQTT password.
	TokenHashes []string `json:"tokenHashes,omitempty"`
	Rules       []Rule   `json:"rules,omitempty"`
	// ExpiresAt, when non zero, is the instant after which the device no longer authenticates.
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
}

// Decision codes carried on Decision.Code and AuditEvent.Code. They are the wire values of the
// TypeScript DECISION_CODES (and policy.DecisionCode) where one exists, so an audit consumer reads
// Go and TypeScript rows the same way. CodeInvalidCredential is the TypeScript device
// authenticator's answer to every credential problem, which keeps a caller from probing which
// device IDs or keys exist.
const (
	CodeAllowed           = string(policy.CodeAllowed)
	CodeNoPermission      = string(policy.CodeNoPermission)
	CodeIndeterminate     = string(policy.CodePolicyIndeterminate)
	CodeDeviceNotFound    = string(policy.CodeDeviceNotFound)
	CodeDeviceSuspended   = string(policy.CodeDeviceSuspended)
	CodeDeviceRevoked     = string(policy.CodeDeviceRevoked)
	CodeDeviceExpired     = string(policy.CodeDeviceExpired)
	CodeInvalidCredential = "invalid_credential"
)

// Active reports whether the device may authenticate or be authorized at now.
func (d *Device) Active(now time.Time) bool { return d.InactiveCode(now) == "" }

// InactiveCode is empty for a device that may act at now, else device_suspended, device_revoked or
// device_expired. A nil device or an unknown status counts as revoked (fail closed). Revoked wins
// over expired, like the TypeScript registry.
func (d *Device) InactiveCode(now time.Time) string {
	switch {
	case d == nil:
		return CodeDeviceRevoked
	case d.Status == StatusRevoked:
		return CodeDeviceRevoked
	case d.Status == StatusSuspended:
		return CodeDeviceSuspended
	case d.Status != StatusActive:
		return CodeDeviceRevoked
	case !d.ExpiresAt.IsZero() && !now.Before(d.ExpiresAt):
		return CodeDeviceExpired
	}
	return ""
}

// ValidateIdentifier checks a value that is substituted into a topic filter: no MQTT wildcard,
// "/", NUL, braces or whitespace, so a device cannot widen a filter through its own ID.
func ValidateIdentifier(kind, v string) error {
	if v == "" {
		return fmt.Errorf("mqttauth: empty %s", kind)
	}
	if len(v) > 256 || strings.ContainsAny(v, "+#/{}$\x00 \t\r\n") {
		return fmt.Errorf("mqttauth: %s %q has characters not allowed in a topic level", kind, v)
	}
	return nil
}

// Validate checks the device record, including every rule filter.
func (d *Device) Validate() error {
	if err := ValidateIdentifier("device id", d.ID); err != nil {
		return err
	}
	if d.OrgID != "" {
		if err := ValidateIdentifier("org id", d.OrgID); err != nil {
			return err
		}
	}
	switch d.Status {
	case StatusActive, StatusSuspended, StatusRevoked:
	default:
		return fmt.Errorf("mqttauth: unknown status %q", d.Status)
	}
	for _, fp := range d.CertFingerprints {
		if n, ok := NormalizeFingerprint(fp); !ok || n != fp {
			return fmt.Errorf("mqttauth: certificate fingerprint %q is not normalized lowercase hex sha256", fp)
		}
	}
	for _, r := range d.Rules {
		if err := r.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (r Rule) validate() error {
	if r.Effect != Allow && r.Effect != Deny {
		return fmt.Errorf("mqttauth: rule effect %q", r.Effect)
	}
	if r.Action != ActionPublish && r.Action != ActionSubscribe && r.Action != ActionAll {
		return fmt.Errorf("mqttauth: rule action %q", r.Action)
	}
	probe := strings.NewReplacer("{device_id}", "x", "{org_id}", "x").Replace(r.Filter)
	if strings.ContainsAny(probe, "{}") {
		return fmt.Errorf("mqttauth: rule filter %q has an unknown placeholder", r.Filter)
	}
	if strings.HasPrefix(probe, "$share/") {
		return fmt.Errorf("mqttauth: rule filter %q: shared subscription prefixes belong in the request, not the rule", r.Filter)
	}
	return ValidateFilter(probe)
}

// HashToken returns the hex SHA-256 digest stored for an opaque device token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NormalizeFingerprint converts "SHA256:AB:CD...", "ab:cd..." or plain hex into lowercase hex
// without separators, and reports whether the result is a SHA-256 digest (64 hex characters).
func NormalizeFingerprint(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i > 0 && strings.EqualFold(strings.ReplaceAll(s[:i], "-", ""), "sha256") {
		s = s[i+1:]
	}
	s = strings.ToLower(strings.ReplaceAll(s, ":", ""))
	if len(s) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", false
	}
	return s, true
}

// DeviceStore is the read side the handler needs. Implementations return ErrDeviceNotFound when
// nothing matches and must not return revoked devices as active.
type DeviceStore interface {
	DeviceByID(ctx context.Context, id string) (*Device, error)
	// DeviceBySubject finds a device by Device.Subject.
	DeviceBySubject(ctx context.Context, subject string) (*Device, error)
	// DeviceByCertFingerprint takes a normalized fingerprint.
	DeviceByCertFingerprint(ctx context.Context, fingerprint string) (*Device, error)
}

// DeviceWriter is the write side, implemented by MemoryStore and SQLStore.
type DeviceWriter interface {
	DeviceStore
	PutDevice(ctx context.Context, d Device) error
	// SetStatus changes a device's status and reports whether the device existed.
	SetStatus(ctx context.Context, id, status string) (bool, error)
}

// MemoryStore is an in memory DeviceWriter for tests and single process setups.
type MemoryStore struct {
	mu      sync.RWMutex
	devices map[string]Device
}

var _ DeviceWriter = (*MemoryStore)(nil)

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore { return &MemoryStore{devices: map[string]Device{}} }

// PutDevice validates and stores d, replacing a device with the same ID. A certificate
// fingerprint or subject already owned by another device is a conflict.
func (m *MemoryStore) PutDevice(_ context.Context, d Device) error {
	if err := d.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, o := range m.devices {
		if id == d.ID {
			continue
		}
		if d.Subject != "" && o.Subject == d.Subject {
			return fmt.Errorf("mqttauth: subject %q already registered", d.Subject)
		}
		for _, fp := range d.CertFingerprints {
			for _, ofp := range o.CertFingerprints {
				if fp == ofp {
					return fmt.Errorf("mqttauth: certificate fingerprint already registered")
				}
			}
		}
	}
	m.devices[d.ID] = clone(d)
	return nil
}

// SetStatus implements DeviceWriter.
func (m *MemoryStore) SetStatus(_ context.Context, id, status string) (bool, error) {
	if status != StatusActive && status != StatusSuspended && status != StatusRevoked {
		return false, fmt.Errorf("mqttauth: unknown status %q", status)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return false, nil
	}
	d.Status = status
	m.devices[id] = d
	return true, nil
}

// DeviceByID implements DeviceStore.
func (m *MemoryStore) DeviceByID(_ context.Context, id string) (*Device, error) {
	return m.find(func(d Device) bool { return d.ID == id })
}

// DeviceBySubject implements DeviceStore.
func (m *MemoryStore) DeviceBySubject(_ context.Context, subject string) (*Device, error) {
	if subject == "" {
		return nil, ErrDeviceNotFound
	}
	return m.find(func(d Device) bool { return d.Subject == subject })
}

// DeviceByCertFingerprint implements DeviceStore.
func (m *MemoryStore) DeviceByCertFingerprint(_ context.Context, fp string) (*Device, error) {
	return m.find(func(d Device) bool {
		for _, f := range d.CertFingerprints {
			if f == fp {
				return true
			}
		}
		return false
	})
}

func (m *MemoryStore) find(pred func(Device) bool) (*Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.devices))
	for id := range m.devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if d := m.devices[id]; pred(d) {
			c := clone(d)
			return &c, nil
		}
	}
	return nil, ErrDeviceNotFound
}

func clone(d Device) Device {
	d.CertFingerprints = append([]string(nil), d.CertFingerprints...)
	d.TokenHashes = append([]string(nil), d.TokenHashes...)
	d.Rules = append([]Rule(nil), d.Rules...)
	return d
}
