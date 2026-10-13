package mcpresource

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwksCache fetches the AS JWKS document and memoizes the parsed public keys
// keyed by kid. The cache refreshes on:
//
//   - first use,
//   - kid miss (an unfamiliar token arrives and the cached snapshot is older
//     than minRefreshInterval, so a malicious flood cannot weaponise the
//     refresh path),
//   - the configured cacheTTL elapsing.
type jwksCache struct {
	uri        string
	httpClient *http.Client
	ttl        time.Duration

	minRefreshInterval time.Duration

	// maxStale caps how long cached keys are served after a failed refresh.
	// Zero means 1 hour.
	maxStale time.Duration
	// now is the clock; nil means time.Now.
	now func() time.Time

	mu          sync.RWMutex
	keys        map[string]jwksKey
	lastFetched time.Time
}

func newJWKSCache(uri string, client *http.Client, ttl time.Duration) *jwksCache {
	if client == nil {
		client = http.DefaultClient
	}
	return &jwksCache{
		uri:                uri,
		httpClient:         client,
		ttl:                ttl,
		minRefreshInterval: 5 * time.Second,
		keys:               map[string]jwksKey{},
	}
}

// jwksKey is one parsed JWKS entry: the public key (ed25519.PublicKey,
// *ecdsa.PublicKey or *rsa.PublicKey) and the optional "alg" the AS pinned
// on the JWK.
type jwksKey struct {
	key crypto.PublicKey
	alg string
}

// Key returns the public key for kid and enforces the JWK's "alg" pin: when
// the AS declared an alg for the key, a token whose header alg differs is
// refused.
func (c *jwksCache) Key(kid, alg string) (crypto.PublicKey, error) {
	if c == nil {
		return nil, errors.New("mcpresource: jwks cache not initialised")
	}
	k, err := c.lookup(kid)
	if err != nil {
		return nil, err
	}
	if k.alg != "" && k.alg != alg {
		return nil, fmt.Errorf("mcpresource: key %q is pinned to alg %q, token uses %q", kid, k.alg, alg)
	}
	return k.key, nil
}

// PublicKey returns the public key for the supplied kid. Triggers a
// refresh on a miss when the cache has aged past minRefreshInterval. Returns
// an error when the kid is still absent after the refresh.
func (c *jwksCache) PublicKey(kid string) (crypto.PublicKey, error) {
	if c == nil {
		return nil, errors.New("mcpresource: jwks cache not initialised")
	}
	k, err := c.lookup(kid)
	if err != nil {
		return nil, err
	}
	return k.key, nil
}

func (c *jwksCache) lookup(kid string) (jwksKey, error) {
	c.mu.RLock()
	pub, ok := c.keys[kid]
	stale := c.clock().Sub(c.lastFetched) > c.ttl
	c.mu.RUnlock()
	if ok && !stale {
		return pub, nil
	}
	// Refresh path: kid miss OR stale snapshot.
	if err := c.refresh(); err != nil {
		// Fall through to stale read if available; otherwise surface the
		// fetch error so the middleware returns 401.
		c.mu.RLock()
		pub, ok := c.keys[kid]
		age := c.clock().Sub(c.lastFetched)
		c.mu.RUnlock()
		if ok && age <= c.staleLimit() {
			return pub, nil
		}
		return jwksKey{}, err
	}
	c.mu.RLock()
	pub, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return jwksKey{}, fmt.Errorf("mcpresource: unknown kid %q", kid)
	}
	return pub, nil
}

func (c *jwksCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *jwksCache) staleLimit() time.Duration {
	if c.maxStale > 0 {
		return c.maxStale
	}
	return time.Hour
}

// refresh pulls the JWKS document and rebuilds the cache. Throttled by
// minRefreshInterval so a flood of unknown-kid tokens cannot DoS the AS.
func (c *jwksCache) refresh() error {
	c.mu.Lock()
	if c.clock().Sub(c.lastFetched) < c.minRefreshInterval && len(c.keys) > 0 {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	req, err := http.NewRequest(http.MethodGet, c.uri, nil)
	if err != nil {
		return fmt.Errorf("mcpresource: jwks request build: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("mcpresource: jwks fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mcpresource: jwks fetch status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("mcpresource: jwks read: %w", err)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			N   string `json:"n"`
			E   string `json:"e"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("mcpresource: jwks parse: %w", err)
	}
	fresh := map[string]jwksKey{}
	malformed := 0
	for _, k := range doc.Keys {
		// Keys of an unsupported type, or published for encryption, are
		// legitimately ignored (the AS may publish more than the verifier
		// accepts), but an Ed25519, P-256 or RSA entry that cannot be
		// parsed is counted and reported.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		var pub crypto.PublicKey
		var err error
		switch {
		case k.Kty == "OKP" && k.Crv == "Ed25519":
			pub, err = parseEd25519JWK(k.X)
		case k.Kty == "EC" && k.Crv == "P-256":
			pub, err = parseP256JWK(k.X, k.Y)
		case k.Kty == "RSA":
			pub, err = parseRSAJWK(k.N, k.E)
		default:
			continue
		}
		if k.Kid == "" || err != nil {
			malformed++
			continue
		}
		fresh[k.Kid] = jwksKey{key: pub, alg: k.Alg}
	}
	// Never replace a working key set with an empty one: that would turn a
	// malformed or truncated document into an outage with no explanation.
	if len(fresh) == 0 {
		return fmt.Errorf("mcpresource: jwks has no usable signing keys (%d of %d entries malformed)", malformed, len(doc.Keys))
	}
	c.mu.Lock()
	c.keys = fresh
	c.lastFetched = c.clock()
	c.mu.Unlock()
	return nil
}

// forceRefresh invalidates the cache so the next PublicKey call hits the
// network. Used by tests to assert kid-miss refresh behaviour.
func (c *jwksCache) forceRefresh() {
	c.mu.Lock()
	c.lastFetched = time.Time{}
	c.mu.Unlock()
}

func parseEd25519JWK(x string) (crypto.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("bad Ed25519 key")
	}
	return ed25519.PublicKey(raw), nil
}

func parseP256JWK(x, y string) (crypto.PublicKey, error) {
	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil || len(xb) != 32 {
		return nil, errors.New("bad P-256 x")
	}
	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil || len(yb) != 32 {
		return nil, errors.New("bad P-256 y")
	}
	point := append([]byte{0x04}, append(xb, yb...)...)
	// ParseUncompressedPublicKey rejects points that are not on the curve.
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("bad P-256 point: %w", err)
	}
	return pub, nil
}

func parseRSAJWK(n, e string) (crypto.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil || len(nb) == 0 {
		return nil, errors.New("bad RSA n")
	}
	eb, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil || len(eb) == 0 || len(eb) > 4 {
		return nil, errors.New("bad RSA e")
	}
	mod := new(big.Int).SetBytes(nb)
	if mod.BitLen() < minRSABits {
		return nil, errors.New("RSA key below 2048 bits")
	}
	exp := int(new(big.Int).SetBytes(eb).Int64())
	if exp < 3 || exp%2 == 0 {
		return nil, errors.New("bad RSA exponent")
	}
	return &rsa.PublicKey{N: mod, E: exp}, nil
}
