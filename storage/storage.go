package storage

import (
	"github.com/glincker/theauth-go"
)

// ErrNotFound is returned by storage adapters when a lookup misses.
// Service code translates to theauth sentinel errors as appropriate.
// Aliased to theauth.ErrStorageNotFound so that root-package service code
// can errors.Is-check without importing this package (which would create
// an import cycle).
var ErrNotFound = theauth.ErrStorageNotFound

// Storage is the persistence contract TheAuth depends on.
// Re-exported from the root package so adapters can reference the
// conventional location while the root package owns the interface
// definition (avoids a root -> storage -> root import cycle).
type Storage = theauth.Storage
