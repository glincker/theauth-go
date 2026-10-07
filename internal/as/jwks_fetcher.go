package as

// jwks_fetcher.go: SSRF-guarded, bounded, expiring fetcher for remote JWKS
// documents (client jwks_uri and TrustedJWTIssuer.JWKSURL).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/internal/safehttp"
)

const (
	// DefaultJWKSCacheTTL bounds how long a fetched JWKS is reused before
	// it is fetched again, so rotated keys are picked up.
	DefaultJWKSCacheTTL = 5 * time.Minute

	// DefaultJWKSCacheMaxEntries bounds the number of distinct JWKS URLs
	// kept in memory. URLs can be attacker-influenced (client jwks_uri).
	DefaultJWKSCacheMaxEntries = 256

	// DefaultJWKSFetchTimeout is the total time allowed for one JWKS fetch.
	DefaultJWKSFetchTimeout = 5 * time.Second

	// maxJWKSBytes caps the size of a JWKS response body.
	maxJWKSBytes = 512 * 1024
)

// Errors returned by the JWKS fetcher. They are wrapped with the URL.
var (
	// ErrJWKSInsecureURL is returned for a non-https JWKS URL when private
	// networks are not allowed.
	ErrJWKSInsecureURL = errors.New("jwks url must be https")
	// ErrJWKSStatus is returned when the JWKS endpoint answers non-200.
	ErrJWKSStatus = errors.New("jwks endpoint returned a non-200 status")
	// ErrJWKSTooLarge is returned when the JWKS body exceeds the size cap.
	ErrJWKSTooLarge = errors.New("jwks document exceeds size limit")
)

type jwksCacheEntry struct {
	keys      []jwksEntry
	expiresAt time.Time
}

// jwksFetcher fetches and caches JWKS documents. Safe for concurrent use.
type jwksFetcher struct {
	client       *http.Client
	allowPrivate bool
	ttl          time.Duration
	maxEntries   int
	now          func() time.Time

	mu      sync.Mutex
	entries map[string]jwksCacheEntry
}

// newJWKSFetcher builds a fetcher from cfg. cfg may be nil, in which case
// every default applies.
func newJWKSFetcher(cfg *JWTBearerConfig) *jwksFetcher {
	f := &jwksFetcher{
		ttl:        DefaultJWKSCacheTTL,
		maxEntries: DefaultJWKSCacheMaxEntries,
		now:        time.Now,
		entries:    map[string]jwksCacheEntry{},
	}
	timeout := DefaultJWKSFetchTimeout
	if cfg != nil {
		f.allowPrivate = cfg.AllowPrivateJWKSNetworks
		if cfg.JWKSCacheTTL > 0 {
			f.ttl = cfg.JWKSCacheTTL
		}
		if cfg.JWKSCacheMaxEntries > 0 {
			f.maxEntries = cfg.JWKSCacheMaxEntries
		}
		if cfg.JWKSFetchTimeout > 0 {
			timeout = cfg.JWKSFetchTimeout
		}
		f.client = cfg.JWKSHTTPClient
	}
	if f.client == nil {
		f.client = safehttp.NewClient(timeout, f.allowPrivate)
	}
	return f
}

// Fetch returns the parsed keys for jwksURL, from cache when fresh.
// Failures are never cached.
func (f *jwksFetcher) Fetch(ctx context.Context, jwksURL string) ([]jwksEntry, error) {
	if keys, ok := f.cached(jwksURL); ok {
		return keys, nil
	}
	u, err := url.Parse(jwksURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("fetch jwks %q: invalid url", jwksURL)
	}
	if u.Scheme != "https" && (!f.allowPrivate || u.Scheme != "http") {
		return nil, fmt.Errorf("fetch jwks %q: %w", jwksURL, ErrJWKSInsecureURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks %q: %w", jwksURL, err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks %q: %w", jwksURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks %q: %w: %d", jwksURL, ErrJWKSStatus, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read jwks %q: %w", jwksURL, err)
	}
	if len(raw) > maxJWKSBytes {
		return nil, fmt.Errorf("read jwks %q: %w", jwksURL, ErrJWKSTooLarge)
	}
	keys, err := parseJWKSBytes(raw)
	if err != nil {
		return nil, err
	}
	f.store(jwksURL, keys)
	return keys, nil
}

func (f *jwksFetcher) cached(jwksURL string) ([]jwksEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[jwksURL]
	if !ok {
		return nil, false
	}
	if !f.now().Before(e.expiresAt) {
		delete(f.entries, jwksURL)
		return nil, false
	}
	return e.keys, true
}

// store inserts keys, first dropping expired entries and then, if the
// cache is still full, the entry closest to expiry.
func (f *jwksFetcher) store(jwksURL string, keys []jwksEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if _, exists := f.entries[jwksURL]; !exists {
		for k, e := range f.entries {
			if !now.Before(e.expiresAt) {
				delete(f.entries, k)
			}
		}
		for len(f.entries) >= f.maxEntries {
			var oldestKey string
			var oldest time.Time
			for k, e := range f.entries {
				if oldestKey == "" || e.expiresAt.Before(oldest) {
					oldestKey, oldest = k, e.expiresAt
				}
			}
			delete(f.entries, oldestKey)
		}
	}
	f.entries[jwksURL] = jwksCacheEntry{keys: keys, expiresAt: now.Add(f.ttl)}
}

// size reports the number of cached entries (including not yet purged
// expired ones). Test helper.
func (f *jwksFetcher) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}
