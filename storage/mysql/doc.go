// Package mysql provides a MySQL 8.x-backed storage.Storage implementation using database/sql and github.com/go-sql-driver/mysql.
//
// Migrations live under migrations/ and are embedded via go:embed. Call Migrate before constructing a Store.
//
// Set THEAUTH_TEST_MYSQL_DSN to run the contract test suite.
//
// MySQL dialect notes vs Postgres: BYTEA -> VARBINARY(255)/BLOB, text[] -> JSON, JSONB -> JSON, TIMESTAMPTZ -> DATETIME(6) + UTC enforced in DSN, gen_random_uuid() not used (ULIDs generated in application layer), BOOLEAN -> TINYINT(1), RETURNING -> follow-up SELECT after INSERT, ON CONFLICT DO NOTHING -> INSERT IGNORE or INSERT ... ON DUPLICATE KEY UPDATE, Partial unique indexes -> enforced in application layer.
package mysql
