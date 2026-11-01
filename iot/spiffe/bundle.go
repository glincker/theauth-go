package spiffe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"time"
)

// Bundle is the parsed trust bundle of one trust domain (SPIFFE Trust Domain and Bundle, section 4):
// a JWK Set where entries with use x509-svid carry one CA certificate in x5c and entries with use
// jwt-svid carry a public key and a kid. Entries with an unknown use or kty are ignored.
type Bundle struct {
	TrustDomain string
	// Sequence is spiffe_sequence. A refresh that lowers it is refused (rollback).
	Sequence    int64
	HasSequence bool
	// RefreshHint is spiffe_refresh_hint, zero when absent.
	RefreshHint time.Duration
	// X509Authorities may anchor an X.509-SVID chain.
	X509Authorities []*x509.Certificate
	// JWTAuthorities verify JWT-SVIDs, by kid. Values are *rsa.PublicKey or *ecdsa.PublicKey.
	JWTAuthorities map[string]crypto.PublicKey
}

var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// ParseBundle parses a bundle document. skipped counts entries that were ignored because they were
// unusable (not a CA, a private key, no kid). A document with keys but no usable authority is an
// error, an empty keys array is valid and means every authority was revoked.
func ParseBundle(trustDomain string, data []byte) (*Bundle, int, error) {
	var doc struct {
		Keys     []map[string]any `json:"keys"`
		Sequence *float64         `json:"spiffe_sequence"`
		Hint     *float64         `json:"spiffe_refresh_hint"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Keys == nil {
		return nil, 0, errors.New("bundle is not a JWK Set")
	}
	b := &Bundle{TrustDomain: trustDomain, JWTAuthorities: map[string]crypto.PublicKey{}}
	if doc.Sequence != nil {
		s := *doc.Sequence
		if s < 0 || s > 9007199254740991 || s != math.Trunc(s) {
			return nil, 0, errors.New("bundle is not a JWK Set")
		}
		b.Sequence, b.HasSequence = int64(s), true
	}
	if doc.Hint != nil {
		h := *doc.Hint
		if h <= 0 || h > 31_536_000 || h != math.Trunc(h) {
			return nil, 0, errors.New("bundle is not a JWK Set")
		}
		b.RefreshHint = time.Duration(h) * time.Second
	}
	skipped := 0
	for _, key := range doc.Keys {
		if _, ok := key["kty"].(string); !ok {
			return nil, 0, errors.New("bundle is not a JWK Set")
		}
		switch key["use"] {
		case "x509-svid":
			cert := firstX5c(key)
			if cert == nil || !usableAuthority(cert) {
				skipped++
				continue
			}
			b.X509Authorities = append(b.X509Authorities, cert)
		case "jwt-svid":
			kid, _ := key["kid"].(string)
			pub := jwtPublicKey(key)
			if kid == "" || pub == nil || hasPrivateMember(key) {
				skipped++
				continue
			}
			if _, dup := b.JWTAuthorities[kid]; dup {
				return nil, 0, errors.New("bundle repeats a jwt-svid kid")
			}
			b.JWTAuthorities[kid] = pub
		}
	}
	if len(doc.Keys) > 0 && len(b.X509Authorities) == 0 && len(b.JWTAuthorities) == 0 {
		return nil, 0, errors.New("bundle has no usable authority")
	}
	return b, skipped, nil
}

// BundleFromRoots builds a bundle from PEM root certificates, for a trust domain with no JWT-SVIDs.
func BundleFromRoots(trustDomain string, roots ...[]byte) (*Bundle, error) {
	b := &Bundle{TrustDomain: trustDomain, JWTAuthorities: map[string]crypto.PublicKey{}}
	for _, data := range roots {
		rest, found := data, false
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			found = true
			cert, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, errors.New("a root certificate could not be parsed")
			}
			if !usableAuthority(cert) {
				return nil, errors.New("a root is not a CA that may sign certificates")
			}
			b.X509Authorities = append(b.X509Authorities, cert)
		}
		if !found {
			return nil, errors.New("a root certificate could not be parsed")
		}
	}
	if len(b.X509Authorities) == 0 {
		return nil, errors.New("no root certificates given")
	}
	return b, nil
}

func hasPrivateMember(key map[string]any) bool {
	for _, m := range privateJWKMembers {
		if _, ok := key[m]; ok {
			return true
		}
	}
	return false
}

func firstX5c(key map[string]any) *x509.Certificate {
	list, _ := key["x5c"].([]any)
	if len(list) == 0 {
		return nil
	}
	s, _ := list[0].(string)
	der, err := decodeB64(s)
	if err != nil {
		return nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return cert
}

func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("bad base64")
}

// usableAuthority: a bundle authority must be a CA that may sign certificates (X509-SVID sections 4.1 and 4.3).
func usableAuthority(c *x509.Certificate) bool {
	if !c.BasicConstraintsValid || !c.IsCA {
		return false
	}
	return !hasExtension(c, oidKeyUsage) || c.KeyUsage&x509.KeyUsageCertSign != 0
}

func jwtPublicKey(key map[string]any) crypto.PublicKey {
	str := func(k string) string { s, _ := key[k].(string); return s }
	num := func(k string) *big.Int {
		raw, err := base64.RawURLEncoding.DecodeString(str(k))
		if err != nil || len(raw) == 0 {
			return nil
		}
		return new(big.Int).SetBytes(raw)
	}
	switch str("kty") {
	case "RSA":
		n, e := num("n"), num("e")
		if n == nil || e == nil || !e.IsInt64() || e.Int64() > math.MaxInt32 || e.Int64() < 3 {
			return nil
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}
	case "EC":
		var curve elliptic.Curve
		switch str("crv") {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil
		}
		x, y := num("x"), num("y")
		if x == nil || y == nil {
			return nil
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		// A point off the curve would make verification meaningless.
		if _, err := pub.ECDH(); err != nil {
			return nil
		}
		return pub
	}
	return nil
}
