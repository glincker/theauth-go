package spiffe

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"time"
)

// JWTOptions tunes JWT-SVID validation.
type JWTOptions struct {
	// Audience lists the values this service accepts. At least one. The token's aud must contain one.
	Audience []string
	// Now defaults to time.Now().
	Now time.Time
	// ClockSkew defaults to 30s. Set NoSkew for zero.
	ClockSkew time.Duration
	NoSkew    bool
	// MaxTTL is the largest accepted time from now to exp, and from iat to exp when iat is set. Default 1h.
	MaxTTL time.Duration
}

// JWTIdentity is a verified JWT-SVID.
type JWTIdentity struct {
	ID        ID
	Audience  []string
	ExpiresAt time.Time
	KID       string
}

type jwsAlg struct {
	hash crypto.Hash
	kind string // rsa, pss, ec
	size int    // ECDSA coordinate size in bytes
}

// JWT-SVID.md section 2.1: the only accepted algorithms.
var jwtAlgs = map[string]jwsAlg{
	"RS256": {crypto.SHA256, "rsa", 0}, "RS384": {crypto.SHA384, "rsa", 0}, "RS512": {crypto.SHA512, "rsa", 0},
	"PS256": {crypto.SHA256, "pss", 0}, "PS384": {crypto.SHA384, "pss", 0}, "PS512": {crypto.SHA512, "pss", 0},
	"ES256": {crypto.SHA256, "ec", 32}, "ES384": {crypto.SHA384, "ec", 48}, "ES512": {crypto.SHA512, "ec", 66},
}

// VerifyJWT validates a JWT-SVID per JWT-SVID.md: alg checked first against the allowed list
// (2.1), typ JWT or JOSE when set (2.3), no header besides alg, kid and typ, sub a SPIFFE ID, aud
// required and containing one accepted audience (3.2), exp required (3.3), signature checked with a
// jwt-svid key of the trust domain named by sub (4). Beyond the spec kid is required and exp may be
// at most MaxTTL ahead. A JWT-SVID has no proof of possession: it is a bearer credential.
func VerifyJWT(ctx context.Context, token string, store *Store, opts JWTOptions) (*JWTIdentity, *Error) {
	if len(opts.Audience) == 0 {
		return nil, fail(CodeWrongAudience, "no audience configured")
	}
	parts := strings.Split(token, ".")
	if len(token) > 16384 || len(parts) != 3 {
		return nil, fail(CodeMalformed, "not a compact JWS")
	}
	var header map[string]any
	var claims map[string]json.RawMessage
	if decodePart(parts[0], &header) != nil || decodePart(parts[1], &claims) != nil {
		return nil, fail(CodeMalformed, "token could not be decoded")
	}
	algName, _ := header["alg"].(string)
	alg, ok := jwtAlgs[algName]
	if !ok {
		return nil, fail(CodeUnsupportedAlg, "algorithm is not allowed for a JWT-SVID")
	}
	for k := range header {
		if k != "alg" && k != "kid" && k != "typ" {
			return nil, fail(CodeMalformed, "token has a header JWT-SVID does not allow")
		}
	}
	if typ, set := header["typ"]; set && typ != "JWT" && typ != "JOSE" {
		return nil, fail(CodeMalformed, "typ must be JWT or JOSE")
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		return nil, fail(CodeMalformed, "token has no kid")
	}
	var sub string
	if raw, ok := claims["sub"]; !ok || json.Unmarshal(raw, &sub) != nil {
		return nil, fail(CodeMissingClaim, "token has no sub")
	}
	if _, ok := claims["aud"]; !ok {
		return nil, fail(CodeMissingClaim, "token has no aud")
	}
	if _, ok := claims["exp"]; !ok {
		return nil, fail(CodeMissingClaim, "token has no exp")
	}
	id, perr := ParseID(sub)
	if perr != nil {
		return nil, fail(CodeInvalidSPIFFEID, perr.Error())
	}
	if id.Path == "" {
		return nil, fail(CodeInvalidSPIFFEID, "workload SPIFFE ID needs a path")
	}
	bundle := store.Get(ctx, id.TrustDomain)
	if bundle == nil {
		return nil, fail(CodeUntrustedDomain, "no trust bundle for this trust domain")
	}
	key, ok := bundle.JWTAuthorities[kid]
	if !ok {
		return nil, fail(CodeUntrustedChain, "no jwt-svid key with this kid")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !verifyJWS(alg, key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, fail(CodeBadSignature, "JWT-SVID signature is invalid")
	}
	return checkJWTClaims(claims, id, kid, opts)
}

func checkJWTClaims(claims map[string]json.RawMessage, id ID, kid string, opts JWTOptions) (*JWTIdentity, *Error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := opts.ClockSkew
	if skew == 0 && !opts.NoSkew {
		skew = 30 * time.Second
	}
	var aud []string
	var one string
	if json.Unmarshal(claims["aud"], &one) == nil {
		aud = []string{one}
	} else if json.Unmarshal(claims["aud"], &aud) != nil {
		return nil, fail(CodeMissingClaim, "a required claim is invalid")
	}
	if !intersects(aud, opts.Audience) {
		return nil, fail(CodeWrongAudience, "audience does not match")
	}
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return nil, fail(CodeMissingClaim, "a required claim is invalid")
	}
	if raw, has := claims["nbf"]; has {
		nbf, ok := numericDate(raw)
		if !ok {
			return nil, fail(CodeMissingClaim, "a required claim is invalid")
		}
		if now.Add(skew).Before(nbf) {
			return nil, fail(CodeNotYetValid, "JWT-SVID is not valid yet")
		}
	}
	if !now.Add(-skew).Before(exp) {
		return nil, fail(CodeExpired, "JWT-SVID has expired")
	}
	maxTTL := opts.MaxTTL
	if maxTTL == 0 {
		maxTTL = time.Hour
	}
	if exp.Sub(now.Truncate(time.Second)) > maxTTL+skew {
		return nil, fail(CodeLifetimeTooLong, "JWT-SVID expires too far in the future")
	}
	if raw, has := claims["iat"]; has {
		if iat, ok := numericDate(raw); ok && exp.Sub(iat) > maxTTL+skew {
			return nil, fail(CodeLifetimeTooLong, "JWT-SVID expires too far in the future")
		}
	}
	return &JWTIdentity{ID: id, Audience: aud, ExpiresAt: exp, KID: kid}, nil
}

func numericDate(raw json.RawMessage) (time.Time, bool) {
	var f float64
	if json.Unmarshal(raw, &f) != nil {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func decodePart(part string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func verifyJWS(alg jwsAlg, key crypto.PublicKey, input, sig []byte) bool {
	var digest []byte
	switch alg.hash {
	case crypto.SHA256:
		d := sha256.Sum256(input)
		digest = d[:]
	case crypto.SHA384:
		d := sha512.Sum384(input)
		digest = d[:]
	default:
		d := sha512.Sum512(input)
		digest = d[:]
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		switch alg.kind {
		case "rsa":
			return rsa.VerifyPKCS1v15(k, alg.hash, digest, sig) == nil
		case "pss":
			return rsa.VerifyPSS(k, alg.hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		}
	case *ecdsa.PublicKey:
		if alg.kind != "ec" || len(sig) != 2*alg.size || (k.Curve.Params().BitSize+7)/8 != alg.size {
			return false
		}
		r := new(big.Int).SetBytes(sig[:alg.size])
		s := new(big.Int).SetBytes(sig[alg.size:])
		return ecdsa.Verify(k, digest, r, s)
	}
	return false
}
