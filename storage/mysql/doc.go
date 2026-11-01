// Package mysql provides a MySQL 8.x storage.Storage implementation using database/sql and go-sql-driver/mysql.
//
// Migrations are embedded from migrations/; call Migrate before constructing a Store. Set
// THEAUTH_MYSQL_CONTRACT=1 and THEAUTH_TEST_MYSQL_DSN to run the contract suite, which passes on
// MySQL 8.4.11 and runs in CI (.github/workflows/mysql-contract.yml). Other MySQL versions and
// MariaDB have not been tested.
//
// Dialect notes: ULIDs are generated in the application (no gen_random_uuid), RETURNING becomes a
// follow-up SELECT, and partial unique indexes are enforced in application code.
package mysql
