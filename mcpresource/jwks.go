package mcpresource

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	mu          sync.RWMutex
	keys        map[string]ed25519.PublicKey
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
		keys:               map[string]ed25519.PublicKey{},
	}
}

// PublicKey returns the Ed25519 public key for the supplied kid. Triggers a
// refresh on a miss when the cache has aged past minRefreshInterval. Returns
// an error when the kid is still absent after the refresh.
func (c *jwksCache) PublicKey(kid string) (ed25519.PublicKey, error) {
	if c == nil {
		return nil, errors.New("mcpresource: jwks cache not initialised")
	}
	c.mu.RLock()
	pub, ok := c.keys[kid]
	stale := time.Since(c.lastFetched) > c.ttl
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
		c.mu.RUnlock()
		if ok {
			return pub, nil
		}
		return nil, err
	}
	c.mu.RLock()
	pub, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("mcpresource: unknown kid %q", kid)
	}
	return pub, nil
}

// refresh pulls the JWKS document and rebuilds the cache. Throttled by
// minRefreshInterval so a flood of unknown-kid tokens cannot DoS the AS.
func (c *jwksCache) refresh() error {
	c.mu.Lock()
	if time.Since(c.lastFetched) < c.minRefreshInterval && len(c.keys) > 0 {
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
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("mcpresource: jwks parse: %w", err)
	}
	fresh := map[string]ed25519.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		fresh[k.Kid] = ed25519.PublicKey(raw)
	}
	c.mu.Lock()
	c.keys = fresh
	c.lastFetched = time.Now()
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
