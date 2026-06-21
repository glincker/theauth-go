package mcpresource

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// introspectionResult is the parsed RFC 7662 + theauth v2.0 response. Fields
// match (*theauth.IntrospectionResponse) but the package is dependency free
// so we redeclare the JSON shape here.
type introspectionResult struct {
	Active            bool        `json:"active"`
	Scope             string      `json:"scope,omitempty"`
	ClientID          string      `json:"client_id,omitempty"`
	TokenType         string      `json:"token_type,omitempty"`
	Exp               int64       `json:"exp,omitempty"`
	Iat               int64       `json:"iat,omitempty"`
	Sub               string      `json:"sub,omitempty"`
	Aud               string      `json:"aud,omitempty"`
	Iss               string      `json:"iss,omitempty"`
	Jti               string      `json:"jti,omitempty"`
	Act               *actorClaim `json:"act,omitempty"`
	DelegationGrantID string      `json:"delegation_grant_id,omitempty"`
}

// actorClaim mirrors the RFC 8693 section 4.1 nested actor structure.
type actorClaim struct {
	Sub string      `json:"sub"`
	Act *actorClaim `json:"act,omitempty"`
}

// introspectCache memoizes recent introspection results by token hash. TTL
// matches the cacheTTL configured on the Validator; introspection responses
// the AS marks with shorter Cache-Control max-age are honored down to one
// second.
type introspectCache struct {
	uri        string
	clientID   string
	secret     string
	httpClient *http.Client
	ttl        time.Duration

	mu      sync.Mutex
	entries map[string]*introspectCacheEntry
}

type introspectCacheEntry struct {
	expiresAt time.Time
	result    *introspectionResult
}

func newIntrospectCache(uri, clientID, secret string, client *http.Client, ttl time.Duration) *introspectCache {
	if client == nil {
		client = http.DefaultClient
	}
	return &introspectCache{
		uri:        uri,
		clientID:   clientID,
		secret:     secret,
		httpClient: client,
		ttl:        ttl,
		entries:    map[string]*introspectCacheEntry{},
	}
}

// Lookup hits the AS introspection endpoint for the supplied token. The
// returned pointer is owned by the cache; callers must not mutate it. The
// audience parameter is passed through as the OAuth resource form field so
// the AS can re-verify audience binding even on cached entries.
func (c *introspectCache) Lookup(token, audience string) (*introspectionResult, error) {
	if c == nil {
		return nil, errors.New("mcpresource: introspect cache not initialised")
	}
	if c.uri == "" {
		// Introspection not configured: return inactive so chain walks fail
		// closed.
		return &introspectionResult{Active: false}, nil
	}
	key := cacheKey(token, audience)
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok && time.Now().Before(entry.expiresAt) {
		out := entry.result
		c.mu.Unlock()
		return out, nil
	}
	c.mu.Unlock()

	res, ttl, err := c.fetch(token, audience)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = c.ttl
	}
	c.mu.Lock()
	c.entries[key] = &introspectCacheEntry{
		expiresAt: time.Now().Add(ttl),
		result:    res,
	}
	c.mu.Unlock()
	return res, nil
}

// Invalidate drops the cached entry for a token. The middleware calls this on
// any AS-side 401 so a stale "active" answer cannot survive a revocation. The
// token may have been issued with different audiences in different request
// paths; the cache keys on the audience as well, so a precise invalidate is
// safer than wiping the whole cache. We accept the conservative approach of
// clearing every entry that shares the token hash.
func (c *introspectCache) Invalidate(token string) {
	hash := tokenHash(token)
	c.mu.Lock()
	for k := range c.entries {
		if strings.HasPrefix(k, hash+":") {
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()
}

func (c *introspectCache) fetch(token, audience string) (*introspectionResult, time.Duration, error) {
	form := url.Values{}
	form.Set("token", token)
	if audience != "" {
		form.Set("resource", audience)
	}
	req, err := http.NewRequest(http.MethodPost, c.uri, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, fmt.Errorf("mcpresource: introspect build: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.clientID != "" {
		req.SetBasicAuth(c.clientID, c.secret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("mcpresource: introspect call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, 0, fmt.Errorf("mcpresource: introspect 401 (client auth)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("mcpresource: introspect status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("mcpresource: introspect read: %w", err)
	}
	var out introspectionResult
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, 0, fmt.Errorf("mcpresource: introspect parse: %w", err)
	}
	ttl := parseMaxAge(resp.Header.Get("Cache-Control"))
	return &out, ttl, nil
}

// parseMaxAge extracts the max-age directive from a Cache-Control header,
// returning 0 when no directive is present or it cannot be parsed.
func parseMaxAge(header string) time.Duration {
	if header == "" {
		return 0
	}
	parts := strings.Split(header, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if !strings.HasPrefix(p, "max-age=") {
			continue
		}
		var n int
		_, err := fmt.Sscanf(p, "max-age=%d", &n)
		if err != nil || n <= 0 {
			return 0
		}
		return time.Duration(n) * time.Second
	}
	return 0
}

func cacheKey(token, audience string) string {
	return tokenHash(token) + ":" + audience
}

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
