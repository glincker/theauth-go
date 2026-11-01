package device

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
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
	default:
		if pk, ok := newECDSAPublicKey(kid, pub); ok {
			return pk, nil
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
	default:
		canon = ecdsaThumbprintInput(p.key)
	}
	canon = append(canon, `"}`...)
	sum := sha256.Sum256(canon)
	return b64.EncodeToString(sum[:])
}

// JWK renders the public key as a JWK object (RFC 7517), with kid and alg set.
func (p PublicKey) JWK() map[string]any {
	jwk := map[string]any{"kid": p.KID, "alg": string(p.Alg), "use": "sig"}
	switch k := p.key.(type) {
	case ed25519.PublicKey:
		jwk["kty"], jwk["crv"], jwk["x"] = "OKP", "Ed25519", b64.EncodeToString(k)
	default:
		ecdsaJWK(p.key, jwk)
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
		var y []byte
		y, err = b64.DecodeString(str("y"))
		if err != nil {
			return PublicKey{}, errors.New("device: bad JWK point")
		}
		pk, err = ecdsaPublicKeyFromJWK(kid, str("crv"), x, y)
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
	}
	return ecdsaVerify(p, msg, sig)
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
	if k, ok := priv.(ed25519.PrivateKey); ok {
		pub, err := NewPublicKey("", k.Public())
		if err != nil {
			return nil, err
		}
		return &Signer{pub: pub, sign: func(m []byte) ([]byte, error) { return ed25519.Sign(k, m), nil }}, nil
	}
	if sg, ok, err := newECDSASigner(priv, rng); ok {
		return sg, err
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
