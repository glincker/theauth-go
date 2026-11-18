package visitorsignal

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MinMasterSecretLen is the shortest accepted master secret, fixed by the contract.
const MinMasterSecretLen = 32

const (
	hashInfoPrefix   = "visitor-signal/v1"
	sketchInfoPrefix = "visitor-signal/v1/sketch"
	keyLen           = 32
	hashTruncBytes   = 16
)

// Errors returned by the key helpers.
var (
	ErrMasterSecretTooShort = errors.New("visitorsignal: master secret is shorter than 32 bytes")
	ErrUnknownSite          = errors.New("visitorsignal: no master secret for site")
)

// SaltProvider looks up the master secret for a site. The secret comes from
// the integrator's secret store and must never be logged.
type SaltProvider interface {
	MasterSecret(ctx context.Context, siteID string) ([]byte, error)
}

// MemorySaltProvider is a fixed in-memory SaltProvider, handy for tests and
// single-tenant setups.
type MemorySaltProvider struct {
	secrets map[string][]byte
}

// NewMemorySaltProvider copies secrets and rejects any shorter than MinMasterSecretLen.
func NewMemorySaltProvider(secrets map[string][]byte) (*MemorySaltProvider, error) {
	m := make(map[string][]byte, len(secrets))
	for site, s := range secrets {
		if len(s) < MinMasterSecretLen {
			return nil, fmt.Errorf("site %q: %w", site, ErrMasterSecretTooShort)
		}
		m[site] = append([]byte(nil), s...)
	}
	return &MemorySaltProvider{secrets: m}, nil
}

// MasterSecret implements SaltProvider. It returns a copy.
func (p *MemorySaltProvider) MasterSecret(ctx context.Context, siteID string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, ok := p.secrets[siteID]
	if !ok {
		return nil, ErrUnknownSite
	}
	return append([]byte(nil), s...), nil
}

// DeriveKey derives the per-site, per-mode, per-epoch hash key with HKDF-SHA256.
func DeriveKey(master []byte, site string, mode Mode, epoch string) ([]byte, error) {
	return deriveKey(hashInfoPrefix, master, site, mode, epoch)
}

func deriveKey(prefix string, master []byte, site string, mode Mode, epoch string) ([]byte, error) {
	if len(master) < MinMasterSecretLen {
		return nil, ErrMasterSecretTooShort
	}
	if !mode.Valid() {
		return nil, fmt.Errorf("visitorsignal: invalid mode %q", mode)
	}
	// NUL separates the info fields, so a NUL inside one would blur the boundary.
	if site == "" || epoch == "" || strings.ContainsRune(site, 0) || strings.ContainsRune(epoch, 0) {
		return nil, errors.New("visitorsignal: site and epoch must be non-empty and free of NUL")
	}
	info := prefix + "\x00" + site + "\x00" + string(mode) + "\x00" + epoch
	return hkdf.Key(sha256.New, master, make([]byte, keyLen), info, keyLen)
}

// Hasher computes visitor hashes for one site, mode and epoch.
type Hasher struct {
	key []byte
}

// NewHasher derives the key once so many components can be hashed cheaply.
func NewHasher(master []byte, site string, mode Mode, epoch string) (*Hasher, error) {
	key, err := DeriveKey(master, site, mode, epoch)
	if err != nil {
		return nil, err
	}
	return &Hasher{key: key}, nil
}

// Hash returns hex(HMAC-SHA256(key, canonical(c))[:16]).
func (h *Hasher) Hash(c Components) (string, error) {
	canon, err := Canonicalise(c)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, h.key)
	mac.Write(canon)
	return hex.EncodeToString(mac.Sum(nil)[:hashTruncBytes]), nil
}

// HashesEqual compares two hashes in constant time.
func HashesEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// String redacts the derived key (value receiver, so copies redact too) so logging a Hasher never leaks it.
func (h Hasher) String() string { return "visitorsignal.Hasher{redacted}" }

// GoString redacts the key for %#v.
func (h Hasher) GoString() string { return h.String() }

// Format redacts the key for every fmt verb.
func (h Hasher) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, h.String()) }
