// Package memory provides an in-process implementation of theauth.Storage
// backed by Go maps protected by a sync.RWMutex.
//
// The store is intended for tests, examples, and local development; it
// retains state only for the lifetime of the process and offers no
// persistence guarantees. Production deployments should use
// storage/postgres or another durable backend.
package memory
