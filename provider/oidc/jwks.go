package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const jwksMinRefetch = 30 * time.Second

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type keySet struct {
	uri    string
	client *http.Client

	mu        sync.Mutex
	keys      map[string]any
	fetchedAt time.Time
}

func (k *keySet) key(ctx context.Context, kid string) (any, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}
	if k.keys != nil && time.Since(k.fetchedAt) < jwksMinRefetch {
		return nil, fmt.Errorf("oidc: unknown signing key %q", kid)
	}
	if err := k.fetch(ctx); err != nil {
		return nil, err
	}
	key, ok := k.keys[kid]
	if !ok {
		return nil, fmt.Errorf("oidc: unknown signing key %q", kid)
	}
	return key, nil
}

func (k *keySet) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.uri, nil)
	if err != nil {
		return err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("oidc: fetch jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("oidc: parse jwks: %w", err)
	}
	keys := make(map[string]any, len(doc.Keys))
	for _, j := range doc.Keys {
		if j.Use != "" && j.Use != "sig" {
			continue
		}
		pub, err := j.public()
		if err != nil {
			continue
		}
		keys[j.Kid] = pub
	}
	k.keys = keys
	k.fetchedAt = time.Now()
	return nil
}

func (j jwk) public() (any, error) {
	switch j.Kty {
	case "RSA":
		n, err := b64Int(j.N)
		if err != nil {
			return nil, err
		}
		e, err := b64Int(j.E)
		if err != nil {
			return nil, err
		}
		if !e.IsInt64() {
			return nil, fmt.Errorf("oidc: rsa exponent too large")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("oidc: unsupported curve %q", j.Crv)
		}
		x, err := b64Int(j.X)
		if err != nil {
			return nil, err
		}
		y, err := b64Int(j.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		if _, err := pub.ECDH(); err != nil {
			return nil, fmt.Errorf("oidc: invalid ec key: %w", err)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("oidc: unsupported key type %q", j.Kty)
}

func b64Int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
