// Package models is the internal home for the theauth-go data layer:
// persisted entity structs (User, Session, OAuthClient, Agent, ...), the
// canonical Permission name catalog, and the sentinel errors that storage
// adapters and service code share.
//
// This package is internal. The exported root package
// (github.com/glincker/theauth-go) re-exports every symbol here via type
// aliases (type X = models.X), const aliases (const X = models.X), and
// var aliases (var X = models.X). Compile-time API stability is preserved:
// the alias form keeps every type identity, method set, and exported name
// unchanged for downstream consumers.
//
// The split exists to keep the root package focused on the public service
// surface (TheAuth, Storage, Config) without 600+ lines of struct
// definitions and constant catalogs in the same file tree.
package models
