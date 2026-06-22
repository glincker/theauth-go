// Package mysql provides a MySQL 8.x-backed storage.Storage implementation
// using database/sql and github.com/go-sql-driver/mysql.
//
// Migrations live under migrations/ and are embedded via go:embed. Call
// Migrate before constructing a Store so the schema is in place.
//
// Set THEAUTH_TEST_MYSQL_DSN to run the contract test suite:
//
//	THEAUTH_TEST_MYSQL_DSN='user:pass@tcp(localhost:3306)/theauth?parseTime=true&loc=UTC' \
//	THEAUTH_MYSQL_CONTRACT=1 \
//	go test ./storage/mysql/...
//
// MySQL dialect notes vs Postgres:
//   - BYTEA -> VARBINARY(255) / BLOB
//   - text[] -> JSON
//   - JSONB -> JSON
//   - TIMESTAMPTZ -> DATETIME(6) + UTC enforced in DSN (loc=UTC)
//   - gen_random_uuid() not used; ULIDs are generated in the application layer
//   - BOOLEAN -> TINYINT(1)
//   - RETURNING -> follow-up SELECT after INSERT (or LastInsertId for auto-inc)
//   - ON CONFLICT DO NOTHING -> INSERT IGNORE or INSERT ... ON DUPLICATE KEY UPDATE
//   - Partial unique indexes (WHERE ...) -> enforced in application layer
package mysql
