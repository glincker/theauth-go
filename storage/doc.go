// Package storage re-exports the theauth.Storage interface and the
// canonical ErrNotFound sentinel that adapters return on lookup misses.
//
// Concrete adapters live in sibling sub-packages: storage/memory for tests
// and local development, storage/postgres for production deployments
// backed by pgx and sqlc-generated queries.
package storage
