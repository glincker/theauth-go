// Package sqlite implements theauth storage on a caller-owned *sql.DB using the pure Go modernc.org/sqlite driver.
//
// The caller owns the database and its pragmas: foreign keys must be on for every connection, and busy_timeout plus WAL mode are strongly advised. Schema is managed either by the host (via Migrations and RenderMigrations) or by this package (via Migrate).
package sqlite
