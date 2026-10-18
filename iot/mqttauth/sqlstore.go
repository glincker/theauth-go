package mqttauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SQLSchema creates the tables SQLStore uses. The types are portable across SQLite and
// PostgreSQL. SQLStore.EnsureSchema runs it.
const SQLSchema = `
CREATE TABLE IF NOT EXISTS theauth_mqtt_devices (
	id TEXT PRIMARY KEY,
	org_id TEXT NOT NULL DEFAULT '',
	name TEXT NOT NULL DEFAULT '',
	subject TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	expires_at BIGINT NOT NULL DEFAULT 0,
	rules TEXT NOT NULL DEFAULT '[]',
	token_hashes TEXT NOT NULL DEFAULT '[]'
);
CREATE UNIQUE INDEX IF NOT EXISTS theauth_mqtt_devices_subject ON theauth_mqtt_devices (subject) WHERE subject <> '';
CREATE TABLE IF NOT EXISTS theauth_mqtt_device_certs (
	fingerprint TEXT PRIMARY KEY,
	device_id TEXT NOT NULL REFERENCES theauth_mqtt_devices (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS theauth_mqtt_device_certs_device ON theauth_mqtt_device_certs (device_id);
`

// SQLStore is a DeviceWriter over database/sql. It works with SQLite and PostgreSQL drivers; set
// Postgres for $n placeholders. The caller owns the driver import and the *sql.DB.
type SQLStore struct {
	DB       *sql.DB
	Postgres bool
}

var _ DeviceWriter = (*SQLStore)(nil)

// EnsureSchema creates the tables when they are missing.
func (s *SQLStore) EnsureSchema(ctx context.Context) error {
	for _, stmt := range strings.Split(SQLSchema, ";\n") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("mqttauth: schema: %w", err)
		}
	}
	return nil
}

func (s *SQLStore) q(query string) string {
	if !s.Postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// PutDevice validates and upserts d with its certificate fingerprints in one transaction.
func (s *SQLStore) PutDevice(ctx context.Context, d Device) error {
	if err := d.Validate(); err != nil {
		return err
	}
	rules, err := json.Marshal(nonNilRules(d.Rules))
	if err != nil {
		return err
	}
	hashes, err := json.Marshal(nonNilStrings(d.TokenHashes))
	if err != nil {
		return err
	}
	var exp int64
	if !d.ExpiresAt.IsZero() {
		exp = d.ExpiresAt.Unix()
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM theauth_mqtt_device_certs WHERE device_id = ?`), d.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM theauth_mqtt_devices WHERE id = ?`), d.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO theauth_mqtt_devices
(id, org_id, name, subject, status, expires_at, rules, token_hashes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		d.ID, d.OrgID, d.Name, d.Subject, d.Status, exp, string(rules), string(hashes)); err != nil {
		return fmt.Errorf("mqttauth: insert device: %w", err)
	}
	for _, fp := range d.CertFingerprints {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO theauth_mqtt_device_certs (fingerprint, device_id) VALUES (?, ?)`), fp, d.ID); err != nil {
			return fmt.Errorf("mqttauth: insert certificate fingerprint: %w", err)
		}
	}
	return tx.Commit()
}

// SetStatus implements DeviceWriter.
func (s *SQLStore) SetStatus(ctx context.Context, id, status string) (bool, error) {
	if status != StatusActive && status != StatusSuspended && status != StatusRevoked {
		return false, fmt.Errorf("mqttauth: unknown status %q", status)
	}
	res, err := s.DB.ExecContext(ctx, s.q(`UPDATE theauth_mqtt_devices SET status = ? WHERE id = ?`), status, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

const sqlDeviceCols = `id, org_id, name, subject, status, expires_at, rules, token_hashes`

// DeviceByID implements DeviceStore.
func (s *SQLStore) DeviceByID(ctx context.Context, id string) (*Device, error) {
	return s.one(ctx, `SELECT `+sqlDeviceCols+` FROM theauth_mqtt_devices WHERE id = ?`, id)
}

// DeviceBySubject implements DeviceStore.
func (s *SQLStore) DeviceBySubject(ctx context.Context, subject string) (*Device, error) {
	if subject == "" {
		return nil, ErrDeviceNotFound
	}
	return s.one(ctx, `SELECT `+sqlDeviceCols+` FROM theauth_mqtt_devices WHERE subject = ?`, subject)
}

// DeviceByCertFingerprint implements DeviceStore.
func (s *SQLStore) DeviceByCertFingerprint(ctx context.Context, fp string) (*Device, error) {
	return s.one(ctx, `SELECT `+sqlDeviceCols+` FROM theauth_mqtt_devices
WHERE id = (SELECT device_id FROM theauth_mqtt_device_certs WHERE fingerprint = ?)`, fp)
}

func (s *SQLStore) one(ctx context.Context, query string, arg string) (*Device, error) {
	var (
		d             Device
		exp           int64
		rules, hashes string
	)
	err := s.DB.QueryRowContext(ctx, s.q(query), arg).Scan(&d.ID, &d.OrgID, &d.Name, &d.Subject, &d.Status, &exp, &rules, &hashes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDeviceNotFound
	}
	if err != nil {
		return nil, err
	}
	if exp != 0 {
		d.ExpiresAt = time.Unix(exp, 0).UTC()
	}
	if err := json.Unmarshal([]byte(rules), &d.Rules); err != nil {
		return nil, fmt.Errorf("mqttauth: decode rules: %w", err)
	}
	if err := json.Unmarshal([]byte(hashes), &d.TokenHashes); err != nil {
		return nil, fmt.Errorf("mqttauth: decode token hashes: %w", err)
	}
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT fingerprint FROM theauth_mqtt_device_certs WHERE device_id = ? ORDER BY fingerprint`), d.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		d.CertFingerprints = append(d.CertFingerprints, fp)
	}
	return &d, rows.Err()
}

func nonNilRules(r []Rule) []Rule {
	if r == nil {
		return []Rule{}
	}
	return r
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
