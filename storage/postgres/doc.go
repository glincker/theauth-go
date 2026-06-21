// Package postgres provides a production-grade implementation of
// theauth.Storage backed by PostgreSQL through pgx and sqlc-generated
// query bindings.
//
// Migrations live under migrations/ and are append-only: a renamed
// column ships as a new migration. Use the in-package New constructor
// with a pgxpool.Pool. See STABILITY.md for the rules that govern future
// schema and query changes.
package postgres
