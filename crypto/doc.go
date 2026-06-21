// Package crypto contains the primitives theauth-go uses for password
// hashing (Argon2id), opaque session and reset tokens (crypto/rand plus
// SHA-256), AES-256-GCM symmetric encryption for OAuth tokens at rest,
// PKCE code verifier and S256 challenge generation, and salted SHA-256
// recovery-code hashing.
//
// The functions in this package are safe to call from multiple goroutines.
// They have no internal state. AES key inputs must be exactly 32 bytes
// (see AESKeyLen); pass shorter or longer slices and Encrypt and Decrypt
// return ErrInvalidKeyLength.
package crypto
