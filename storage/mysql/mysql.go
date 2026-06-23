// Package mysql: mysql.go defines the Store type and shared type-mapping
// helpers. All SQL uses database/sql with ? placeholders (MySQL style).
package mysql

import (
	"database/sql"
	"strings"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage"
)

// Compile-time interface assertions: Store must satisfy both core Storage and
// the optional OAuthServerStorage extension.
var _ storage.Storage = (*Store)(nil)
var _ theauth.OAuthServerStorage = (*Store)(nil)

// Store is the MySQL-backed storage adapter.
type Store struct {
	db *sql.DB
}

// New constructs a Store using the given *sql.DB. The caller is responsible
// for calling Migrate before constructing the Store.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// ---------- type-mapping helpers ----------

// ulidToBytes converts a theauth.ULID to a 16-byte slice for BINARY(16).
func ulidToBytes(id theauth.ULID) []byte {
	b := [16]byte(id)
	return b[:]
}

// bytesToULID converts a 16-byte slice from BINARY(16) back to ULID.
func bytesToULID(b []byte) theauth.ULID {
	var id [16]byte
	copy(id[:], b)
	return theauth.ULID(id)
}

// ulidPtrToBytes returns nil when p is nil, otherwise the 16-byte slice.
func ulidPtrToBytes(p *theauth.ULID) []byte {
	if p == nil {
		return nil
	}
	return ulidToBytes(*p)
}

// bytesToULIDPtr returns nil when b is nil or empty.
func bytesToULIDPtr(b []byte) *theauth.ULID {
	if len(b) == 0 {
		return nil
	}
	id := bytesToULID(b)
	return &id
}

// nullTimeToPtr converts a sql.NullTime to *time.Time.
func nullTimeToPtr(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	t := nt.Time.UTC()
	return &t
}

// timePtrToNull converts *time.Time to sql.NullTime.
func timePtrToNull(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}

// timeUTC returns t in UTC (all timestamps are stored as UTC DATETIME(6)).
func timeUTC(t time.Time) time.Time {
	return t.UTC()
}

// nullBytesToSlice returns an empty slice when b is nil/empty.
func nullBytesToSlice(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// isMySQL1062 returns true when the error is a MySQL duplicate-entry error
// (SQLSTATE 23000, MySQL error 1062).
func isMySQL1062(err error) bool {
	if err == nil {
		return false
	}
	// The go-sql-driver/mysql error message always contains "Error 1062".
	return strings.Contains(err.Error(), "1062") ||
		strings.Contains(err.Error(), "Duplicate entry")
}

// nullStringToPtr returns nil when s is empty.
func nullStringVal(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullStringScan(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return ns.String
}
