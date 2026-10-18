package device

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
)

// Alg is a JWS signature algorithm a device key can use. A key is tied to exactly one
// algorithm, so a token header can never pick a weaker one (RFC 8725 section 3.1).
type Alg string

const (
	// AlgES256 is ECDSA over P-256 with SHA-256 (RFC 7518 section 3.4).
	AlgES256 Alg = "ES256"
	// AlgES384 is ECDSA over P-384 with SHA-384. Accepted for device assertions only.
	AlgES384 Alg = "ES384"
	// AlgEdDSA is Ed25519 (RFC 8037, RFC 8032).
	AlgEdDSA Alg = "EdDSA"
)

var b64 = base64.RawURLEncoding

// PublicKey is a verification key with its key id.
type PublicKey struct {
	KID string
	Alg Alg
	key crypto.PublicKey
}

// NewPublicKey wraps an *ecdsa.PublicKey (P-256 or P-384) or an ed25519.PublicKey.
func NewPublicKey(kid string, pub crypto.PublicKey) (PublicKey, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return PublicKey{}, errors.New("device: bad Ed25519 public key length")
		}
		return PublicKey{KID: kid, Alg: AlgEdDSA, key: k}, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return PublicKey{KID: kid, Alg: AlgES256, key: k}, nil
		case elliptic.P384():
			return PublicKey{KID: kid, Alg: AlgES384, key: k}, nil
		}
	}
	return PublicKey{}, errors.New("device: key must be EC P-256, EC P-384 or Ed25519")
}

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint, base64url encoded. It is the
// `kid` of a device assertion.
func (p PublicKey) Thumbprint() string {
	var canon []byte
	switch k := p.key.(type) {
	case ed25519.PublicKey:
		canon = append(canon, `{"crv":"Ed25519","kty":"OKP","x":"`...)
		canon = append(canon, b64.EncodeToString(k)...)
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		canon = append(canon, `{"crv":"`...)
		canon = append(canon, curveName(k.Curve)...)
		canon = append(canon, `","kty":"EC","x":"`...)
		canon = append(canon, b64.EncodeToString(k.X.FillBytes(make([]byte, size)))...)
		canon = append(canon, `","y":"`...)
		canon = append(canon, b64.EncodeToString(k.Y.FillBytes(make([]byte, size)))...)
	}
	canon = append(canon, `"}`...)
	sum := sha256.Sum256(canon)
	return b64.EncodeToString(sum[:])
}

func curveName(c elliptic.Curve) string {
	if c == elliptic.P384() {
		return "P-384"
	}
	return "P-256"
}

// JWK renders the public key as a JWK object (RFC 7517), with kid and alg set.
func (p PublicKey) JWK() map[string]any {
	jwk := map[string]any{"kid": p.KID, "alg": string(p.Alg), "use": "sig"}
	switch k := p.key.(type) {
	case ed25519.PublicKey:
		jwk["kty"], jwk["crv"], jwk["x"] = "OKP", "Ed25519", b64.EncodeToString(k)
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		jwk["kty"], jwk["crv"] = "EC", curveName(k.Curve)
		jwk["x"] = b64.EncodeToString(k.X.FillBytes(make([]byte, size)))
		jwk["y"] = b64.EncodeToString(k.Y.FillBytes(make([]byte, size)))
	}
	return jwk
}

// KeySet is a set of verification keys looked up by `kid`, usually parsed from
// `GET /device/jwks`.
type KeySet struct{ keys []PublicKey }

// NewKeySet builds a set from keys you already hold.
func NewKeySet(keys ...PublicKey) *KeySet { return &KeySet{keys: keys} }

// Lookup returns the key with this kid.
func (s *KeySet) Lookup(kid string) (PublicKey, bool) {
	if s != nil {
		for _, k := range s.keys {
			if k.KID == kid {
				return k, true
			}
		}
	}
	return PublicKey{}, false
}

// ParseJWKS reads a JWK Set (RFC 7517 section 5). Keys it cannot use (unsupported type,
// no kid, malformed point, private members) are skipped, so one odd entry never blocks
// the rest. It errors only when the document is not a JWKS.
func ParseJWKS(data []byte) (*KeySet, error) {
	doc, err := parseJSON(data)
	if err != nil {
		return nil, err
	}
	obj, _ := doc.(map[string]any)
	list, ok := obj["keys"].([]any)
	if !ok {
		return nil, errors.New("device: JWKS has no keys array")
	}
	set := &KeySet{}
	for _, e := range list {
		if jwk, ok := e.(map[string]any); ok {
			if pk, err := publicKeyFromJWK(jwk); err == nil {
				set.keys = append(set.keys, pk)
			}
		}
	}
	return set, nil
}

func publicKeyFromJWK(jwk map[string]any) (PublicKey, error) {
	str := func(name string) string { s, _ := jwk[name].(string); return s }
	kid := str("kid")
	if kid == "" {
		return PublicKey{}, errors.New("device: JWK has no kid")
	}
	for _, m := range [...]string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, bad := jwk[m]; bad {
			return PublicKey{}, errors.New("device: JWK carries private members")
		}
	}
	x, err := b64.DecodeString(str("x"))
	if err != nil {
		return PublicKey{}, errors.New("device: bad JWK x")
	}
	var pk PublicKey
	switch {
	case str("kty") == "OKP" && str("crv") == "Ed25519":
		pk, err = NewPublicKey(kid, ed25519.PublicKey(x))
	case str("kty") == "EC" && (str("crv") == "P-256" || str("crv") == "P-384"):
		curve := elliptic.P256()
		if str("crv") == "P-384" {
			curve = elliptic.P384()
		}
		size := (curve.Params().BitSize + 7) / 8
		y, yerr := b64.DecodeString(str("y"))
		if yerr != nil || len(x) != size || len(y) != size {
			return PublicKey{}, errors.New("device: bad JWK point")
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if _, perr := pub.ECDH(); perr != nil {
			return PublicKey{}, errors.New("device: JWK point is not on the curve")
		}
		pk, err = NewPublicKey(kid, pub)
	default:
		return PublicKey{}, errors.New("device: unsupported JWK type")
	}
	if err != nil {
		return PublicKey{}, err
	}
	if a := str("alg"); a != "" && a != string(pk.Alg) {
		return PublicKey{}, errors.New("device: JWK alg does not match its key")
	}
	return pk, nil
}

func hashFor(a Alg, msg []byte) []byte {
	if a == AlgES384 {
		s := sha512.Sum384(msg)
		return s[:]
	}
	s := sha256.Sum256(msg)
	return s[:]
}

func sigSize(a Alg) int {
	switch a {
	case AlgES384:
		return 96
	case AlgES256:
		return 64
	}
	return ed25519.SignatureSize
}

// verifySig checks a JWS signature (raw r||s for ECDSA, RFC 7518 section 3.4).
func (p PublicKey) verifySig(msg, sig []byte) bool {
	if len(sig) != sigSize(p.Alg) {
		return false
	}
	switch k := p.key.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(k, msg, sig)
	case *ecdsa.PublicKey:
		half := len(sig) / 2
		der := derFromRS(sig[:half], sig[half:])
		return ecdsa.VerifyASN1(k, hashFor(p.Alg, msg), der)
	}
	return false
}

// Signer signs with one private key. Build it with NewSigner.
type Signer struct {
	pub  PublicKey
	sign func(msg []byte) ([]byte, error)
}

// NewSigner accepts an ed25519.PrivateKey or an *ecdsa.PrivateKey on P-256 or P-384. rng
// feeds ECDSA nonces and may be nil (crypto/rand is used); Ed25519 is deterministic and
// never reads it, which matters on parts without a hardware random source.
func NewSigner(priv crypto.PrivateKey, rng io.Reader) (*Signer, error) {
	if rng == nil {
		rng = rand.Reader
	}
	switch k := priv.(type) {
	case ed25519.PrivateKey:
		pub, err := NewPublicKey("", k.Public())
		if err != nil {
			return nil, err
		}
		return &Signer{pub: pub, sign: func(m []byte) ([]byte, error) { return ed25519.Sign(k, m), nil }}, nil
	case *ecdsa.PrivateKey:
		pub, err := NewPublicKey("", &k.PublicKey)
		if err != nil {
			return nil, err
		}
		alg := pub.Alg
		return &Signer{pub: pub, sign: func(m []byte) ([]byte, error) {
			der, err := ecdsa.SignASN1(rng, k, hashFor(alg, m))
			if err != nil {
				return nil, err
			}
			return rsFromDER(der, sigSize(alg)/2)
		}}, nil
	}
	return nil, errors.New("device: key must be ed25519.PrivateKey or *ecdsa.PrivateKey")
}

// Alg is the algorithm this signer produces.
func (s *Signer) Alg() Alg { return s.pub.Alg }

// Public returns the verification key with its RFC 7638 thumbprint as kid.
func (s *Signer) Public() PublicKey {
	p := s.pub
	p.KID = p.Thumbprint()
	return p
}

func derInt(dst, v []byte) []byte {
	for len(v) > 1 && v[0] == 0 {
		v = v[1:]
	}
	n := len(v)
	pad := v[0]&0x80 != 0
	if pad {
		n++
	}
	dst = append(dst, 0x02, byte(n))
	if pad {
		dst = append(dst, 0)
	}
	return append(dst, v...)
}

func derFromRS(r, s []byte) []byte {
	body := derInt(nil, r)
	body = derInt(body, s)
	return append([]byte{0x30, byte(len(body))}, body...)
}

func rsFromDER(der []byte, size int) ([]byte, error) {
	bad := errors.New("device: bad ECDSA signature encoding")
	if len(der) < 8 || der[0] != 0x30 || int(der[1]) != len(der)-2 {
		return nil, bad
	}
	out := make([]byte, 2*size)
	rest := der[2:]
	for i := 0; i < 2; i++ {
		if len(rest) < 2 || rest[0] != 0x02 || int(rest[1]) > len(rest)-2 {
			return nil, bad
		}
		v := rest[2 : 2+int(rest[1])]
		rest = rest[2+int(rest[1]):]
		for len(v) > size && v[0] == 0 {
			v = v[1:]
		}
		if len(v) > size {
			return nil, bad
		}
		copy(out[i*size+size-len(v):], v)
	}
	if len(rest) != 0 {
		return nil, bad
	}
	return out, nil
}
