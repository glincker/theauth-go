package mqttauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
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

// pgQueries memoizes the $n form of each query text. The queries are string constants, so the map
// stays tiny and the placeholder rewrite runs once per statement instead of once per call.
var pgQueries sync.Map

func (s *SQLStore) q(query string) string {
	if !s.Postgres {
		return query
	}
	if v, ok := pgQueries.Load(query); ok {
		return v.(string)
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
	pgQueries.Store(query, b.String())
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

// sqlDeviceJoin selects the device row together with its certificate fingerprints in one round
// trip: one row per fingerprint, or one row with a NULL fingerprint when the device has none.
const sqlDeviceJoin = `SELECT d.id, d.org_id, d.name, d.subject, d.status, d.expires_at, d.rules, d.token_hashes, c.fingerprint
FROM theauth_mqtt_devices d LEFT JOIN theauth_mqtt_device_certs c ON c.device_id = d.id`

// DeviceByID implements DeviceStore.
func (s *SQLStore) DeviceByID(ctx context.Context, id string) (*Device, error) {
	return s.one(ctx, sqlDeviceJoin+` WHERE d.id = ? ORDER BY c.fingerprint`, id)
}

// DeviceBySubject implements DeviceStore. The subject <> ” term is redundant with the argument
// check above it, but it lets the planner use the partial unique index (theauth_mqtt_devices_subject
// only covers non empty subjects), which it cannot prove from a bound parameter alone.
func (s *SQLStore) DeviceBySubject(ctx context.Context, subject string) (*Device, error) {
	if subject == "" {
		return nil, ErrDeviceNotFound
	}
	return s.one(ctx, sqlDeviceJoin+` WHERE d.subject = ? AND d.subject <> '' ORDER BY c.fingerprint`, subject)
}

// DeviceByCertFingerprint implements DeviceStore.
func (s *SQLStore) DeviceByCertFingerprint(ctx context.Context, fp string) (*Device, error) {
	return s.one(ctx, sqlDeviceJoin+`
WHERE d.id = (SELECT device_id FROM theauth_mqtt_device_certs WHERE fingerprint = ?) ORDER BY c.fingerprint`, fp)
}

func (s *SQLStore) one(ctx context.Context, query string, arg string) (*Device, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(query), arg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var d *Device
	for rows.Next() {
		var (
			row           Device
			exp           int64
			rules, hashes string
			fp            sql.NullString
		)
		if err := rows.Scan(&row.ID, &row.OrgID, &row.Name, &row.Subject, &row.Status, &exp, &rules, &hashes, &fp); err != nil {
			return nil, err
		}
		if d == nil {
			if exp != 0 {
				row.ExpiresAt = time.Unix(exp, 0).UTC()
			}
			if err := json.Unmarshal([]byte(rules), &row.Rules); err != nil {
				return nil, fmt.Errorf("mqttauth: decode rules: %w", err)
			}
			if err := json.Unmarshal([]byte(hashes), &row.TokenHashes); err != nil {
				return nil, fmt.Errorf("mqttauth: decode token hashes: %w", err)
			}
			d = &row
		}
		if fp.Valid {
			d.CertFingerprints = append(d.CertFingerprints, fp.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if d == nil {
		return nil, ErrDeviceNotFound
	}
	return d, nil
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
