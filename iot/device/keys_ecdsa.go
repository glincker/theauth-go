//go:build !theauth_noecdsa

package device

// keys_ecdsa.go holds every ECDSA code path (ES256 and ES384). Build with -tags theauth_noecdsa to
// leave it out: the binary then handles Ed25519 only, and crypto/ecdsa, crypto/elliptic and
// math/big drop out. On TinyGo that frees about 100 kB of RAM (the P-256 tables), see
// docs/iot-device-client.md.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"
)

func newECDSAPublicKey(kid string, pub crypto.PublicKey) (PublicKey, bool) {
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return PublicKey{}, false
	}
	switch k.Curve {
	case elliptic.P256():
		return PublicKey{KID: kid, Alg: AlgES256, key: k}, true
	case elliptic.P384():
		return PublicKey{KID: kid, Alg: AlgES384, key: k}, true
	}
	return PublicKey{}, false
}

// ecdsaThumbprintInput returns the RFC 7638 canonical members up to, not including, the closing quote of y.
func ecdsaThumbprintInput(key crypto.PublicKey) []byte {
	k, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil
	}
	size := (k.Curve.Params().BitSize + 7) / 8
	var canon []byte
	canon = append(canon, `{"crv":"`...)
	canon = append(canon, curveName(k.Curve)...)
	canon = append(canon, `","kty":"EC","x":"`...)
	canon = append(canon, b64.EncodeToString(k.X.FillBytes(make([]byte, size)))...)
	canon = append(canon, `","y":"`...)
	canon = append(canon, b64.EncodeToString(k.Y.FillBytes(make([]byte, size)))...)
	return canon
}

func curveName(c elliptic.Curve) string {
	if c == elliptic.P384() {
		return "P-384"
	}
	return "P-256"
}

func ecdsaJWK(key crypto.PublicKey, jwk map[string]any) {
	k, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return
	}
	size := (k.Curve.Params().BitSize + 7) / 8
	jwk["kty"], jwk["crv"] = "EC", curveName(k.Curve)
	jwk["x"] = b64.EncodeToString(k.X.FillBytes(make([]byte, size)))
	jwk["y"] = b64.EncodeToString(k.Y.FillBytes(make([]byte, size)))
}

func ecdsaPublicKeyFromJWK(kid, crv string, x, y []byte) (PublicKey, error) {
	curve := elliptic.P256()
	if crv == "P-384" {
		curve = elliptic.P384()
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(x) != size || len(y) != size {
		return PublicKey{}, errors.New("device: bad JWK point")
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if _, perr := pub.ECDH(); perr != nil {
		return PublicKey{}, errors.New("device: JWK point is not on the curve")
	}
	return NewPublicKey(kid, pub)
}

func ecdsaVerify(p PublicKey, msg, sig []byte) bool {
	k, ok := p.key.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	half := len(sig) / 2
	der := derFromRS(sig[:half], sig[half:])
	return ecdsa.VerifyASN1(k, hashFor(p.Alg, msg), der)
}

func newECDSASigner(priv crypto.PrivateKey, rng io.Reader) (*Signer, bool, error) {
	k, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, false, nil
	}
	pub, err := NewPublicKey("", &k.PublicKey)
	if err != nil {
		return nil, true, err
	}
	alg := pub.Alg
	return &Signer{pub: pub, sign: func(m []byte) ([]byte, error) {
		der, err := ecdsa.SignASN1(rng, k, hashFor(alg, m))
		if err != nil {
			return nil, err
		}
		return rsFromDER(der, sigSize(alg)/2)
	}}, true, nil
}

func hashFor(a Alg, msg []byte) []byte {
	if a == AlgES384 {
		s := sha512.Sum384(msg)
		return s[:]
	}
	s := sha256.Sum256(msg)
	return s[:]
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
