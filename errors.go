package theauth

import "errors"

var (
	ErrInvalidToken     = errors.New("theauth: invalid token")
	ErrSessionExpired   = errors.New("theauth: session expired")
	ErrUserNotFound     = errors.New("theauth: user not found")
	ErrMagicLinkExpired = errors.New("theauth: magic link expired")
	ErrMagicLinkUsed    = errors.New("theauth: magic link already used")
	ErrEmailNotVerified = errors.New("theauth: email not verified")

	// ErrStorageNotFound is the canonical "row missing" sentinel that storage
	// adapters return on lookup misses. Lives in the root package so service
	// code can errors.Is-check without importing the storage package
	// (which would create an import cycle).
	ErrStorageNotFound = errors.New("theauth: storage row not found")
)
