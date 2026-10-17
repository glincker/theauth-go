package tokenvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	sealVersion = 1
	keySize     = 32
	maxKeyIDLen = 255
)

// Errors returned by the key ring.
var (
	// ErrUnknownKey means a sealed blob names a key id the ring does not hold.
	ErrUnknownKey = errors.New("tokenvault: unknown key id")
	// ErrDecrypt means a blob failed authentication: wrong key, wrong binding
	// or tampered bytes. The cause is deliberately not distinguished.
	ErrDecrypt = errors.New("tokenvault: cannot decrypt")
	// ErrMalformed means a blob is too short or has an unsupported version.
	ErrMalformed = errors.New("tokenvault: malformed ciphertext")
)

// KeyRing holds AES-256 keys by id and names the active one used for new
// blobs. Older keys stay in the ring so existing blobs remain readable until
// Vault.Rewrap has moved them to the active key.
type KeyRing struct {
	active string
	aeads  map[string]cipher.AEAD
	rand   io.Reader
}

// NewKeyRing builds a ring. Every key must be exactly 32 bytes and every id
// 1 to 255 bytes. activeID must be present in keys. The key bytes are copied.
func NewKeyRing(activeID string, keys map[string][]byte) (*KeyRing, error) {
	if _, ok := keys[activeID]; !ok {
		return nil, fmt.Errorf("tokenvault: active key id %q not in ring", activeID)
	}
	r := &KeyRing{active: activeID, aeads: make(map[string]cipher.AEAD, len(keys)), rand: rand.Reader}
	for id, k := range keys {
		if id == "" || len(id) > maxKeyIDLen {
			return nil, errors.New("tokenvault: key id must be 1 to 255 bytes")
		}
		if len(k) != keySize {
			return nil, fmt.Errorf("tokenvault: key %q must be %d bytes", id, keySize)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("tokenvault: key %q: %w", id, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("tokenvault: key %q: %w", id, err)
		}
		r.aeads[id] = aead
	}
	return r, nil
}

// ActiveID returns the id of the key used by Seal.
func (r *KeyRing) ActiveID() string { return r.active }

// String and GoString never reveal key material.
func (r *KeyRing) String() string { return "tokenvault.KeyRing{active:" + r.active + "}" }

// GoString implements fmt.GoStringer.
func (r *KeyRing) GoString() string { return r.String() }

// Seal encrypts plaintext under the active key. aad binds the blob to its
// context and must be presented again to Open. Layout: version, key id length,
// key id, nonce, ciphertext with tag. The header is authenticated too.
func (r *KeyRing) Seal(plaintext, aad []byte) ([]byte, error) {
	aead := r.aeads[r.active]
	header := make([]byte, 0, 2+len(r.active))
	header = append(header, sealVersion, byte(len(r.active)))
	header = append(header, r.active...)
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(r.rand, nonce); err != nil {
		return nil, fmt.Errorf("tokenvault: nonce: %w", err)
	}
	out := append(header, nonce...)
	return aead.Seal(out, nonce, plaintext, joinAAD(header, aad)), nil
}

// KeyID returns the key id recorded in a sealed blob without decrypting it.
func (r *KeyRing) KeyID(blob []byte) (string, error) {
	id, _, err := parseHeader(blob)
	return id, err
}

// Open decrypts a blob produced by Seal with the same aad.
func (r *KeyRing) Open(blob, aad []byte) ([]byte, error) {
	id, hlen, err := parseHeader(blob)
	if err != nil {
		return nil, err
	}
	aead, ok := r.aeads[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	ns := aead.NonceSize()
	if len(blob) < hlen+ns+aead.Overhead() {
		return nil, ErrMalformed
	}
	pt, err := aead.Open(nil, blob[hlen:hlen+ns], blob[hlen+ns:], joinAAD(blob[:hlen], aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func parseHeader(blob []byte) (id string, hlen int, err error) {
	if len(blob) < 2 || blob[0] != sealVersion {
		return "", 0, ErrMalformed
	}
	n := int(blob[1])
	if n == 0 || len(blob) < 2+n {
		return "", 0, ErrMalformed
	}
	return string(blob[2 : 2+n]), 2 + n, nil
}

func joinAAD(header, aad []byte) []byte {
	out := make([]byte, 0, len(header)+len(aad))
	out = append(out, header...)
	return append(out, aad...)
}
