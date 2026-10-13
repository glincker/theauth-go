package signals

import (
	"context"
	"crypto"
	"crypto/ecdh"
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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/internal/jwt"
)

type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type parsedKey struct {
	alg string
	pub crypto.PublicKey
}

func parseJWK(j jwkKey) (parsedKey, bool) {
	dec := func(v string) ([]byte, bool) {
		b, err := base64.RawURLEncoding.DecodeString(v)
		return b, err == nil && len(b) > 0
	}
	switch j.Kty {
	case "OKP":
		x, ok := dec(j.X)
		if !ok || j.Crv != "Ed25519" || len(x) != ed25519.PublicKeySize {
			return parsedKey{}, false
		}
		return parsedKey{jwt.AlgEdDSA, ed25519.PublicKey(x)}, true
	case "EC":
		x, okx := dec(j.X)
		y, oky := dec(j.Y)
		if !okx || !oky || j.Crv != "P-256" || len(x) > 32 || len(y) > 32 {
			return parsedKey{}, false
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		point := make([]byte, 65)
		point[0] = 4
		pub.X.FillBytes(point[1:33])
		pub.Y.FillBytes(point[33:65])
		if _, err := ecdh.P256().NewPublicKey(point); err != nil {
			return parsedKey{}, false
		}
		return parsedKey{jwt.AlgES256, pub}, true
	case "RSA":
		n, okn := dec(j.N)
		e, oke := dec(j.E)
		if !okn || !oke {
			return parsedKey{}, false
		}
		ev := new(big.Int).SetBytes(e)
		if !ev.IsInt64() || ev.Int64() < 3 || ev.Int64() > 1<<31-1 {
			return parsedKey{}, false
		}
		return parsedKey{jwt.AlgRS256, &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ev.Int64())}}, true
	}
	return parsedKey{}, false
}

// jwksCache fetches and caches issuer key sets through a guarded client.
type jwksCache struct {
	hc       *http.Client
	policy   URLPolicy
	ttl      time.Duration
	cooldown time.Duration
	now      func() time.Time

	mu      sync.Mutex
	entries map[string]*jwksEntry
}

type jwksEntry struct {
	keys      map[string]parsedKey
	fetchedAt time.Time
	jwksURI   string
}

func (c *jwksCache) getJSON(ctx context.Context, u string, v any) error {
	if err := ValidateEndpointURL(ctx, u, c.policy); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s answered %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// wellKnownURL builds the SSF metadata URL for an issuer (SSF section 7.2.1).
func wellKnownURL(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return "", errors.New("signals: issuer is not a URL")
	}
	path := strings.TrimRight(u.Path, "/")
	return u.Scheme + "://" + u.Host + "/.well-known/ssf-configuration" + path, nil
}

func (c *jwksCache) refresh(ctx context.Context, issuer, jwksURI string) (*jwksEntry, error) {
	if jwksURI == "" {
		wk, err := wellKnownURL(issuer)
		if err != nil {
			return nil, err
		}
		var meta struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := c.getJSON(ctx, wk, &meta); err != nil {
			return nil, fmt.Errorf("signals: discover %s: %w", issuer, err)
		}
		if meta.Issuer != "" && meta.Issuer != issuer {
			return nil, errors.New("signals: discovery issuer mismatch")
		}
		if meta.JWKSURI == "" {
			return nil, errors.New("signals: issuer metadata has no jwks_uri")
		}
		jwksURI = meta.JWKSURI
	}
	var doc struct {
		Keys []jwkKey `json:"keys"`
	}
	if err := c.getJSON(ctx, jwksURI, &doc); err != nil {
		return nil, fmt.Errorf("signals: fetch jwks: %w", err)
	}
	e := &jwksEntry{keys: map[string]parsedKey{}, fetchedAt: c.now(), jwksURI: jwksURI}
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if pk, ok := parseJWK(k); ok && k.Kid != "" {
			if k.Alg != "" && k.Alg != pk.alg {
				continue
			}
			e.keys[k.Kid] = pk
		}
	}
	c.mu.Lock()
	c.entries[issuer] = e
	c.mu.Unlock()
	return e, nil
}

// resolver returns a KeyResolver for issuer. A kid miss or a stale entry
// triggers one refetch, rate limited by cooldown.
func (c *jwksCache) resolver(ctx context.Context, issuer, jwksURI string) (KeyResolver, error) {
	c.mu.Lock()
	e := c.entries[issuer]
	c.mu.Unlock()
	if e == nil || c.now().Sub(e.fetchedAt) > c.ttl {
		var err error
		if e, err = c.refresh(ctx, issuer, jwksURI); err != nil {
			return nil, err
		}
	}
	refetched := false
	return func(kid string) (string, crypto.PublicKey, bool) {
		if k, ok := e.keys[kid]; ok {
			return k.alg, k.pub, true
		}
		if !refetched && c.now().Sub(e.fetchedAt) > c.cooldown {
			refetched = true
			if ne, err := c.refresh(ctx, issuer, jwksURI); err == nil {
				e = ne
				if k, ok := e.keys[kid]; ok {
					return k.alg, k.pub, true
				}
			}
		}
		return "", nil, false
	}, nil
}
