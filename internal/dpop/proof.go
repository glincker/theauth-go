package dpop

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// proof.go is the RFC 9449 section 4 proof parser and verifier. It has no third-party JWT
// dependency, so mcpresource can reuse it.

// ProofTyp is the typ value mandated by RFC 9449 section 4.2 for DPoP
// proof JWTs. Verification rejects any other value.
const ProofTyp = "dpop+jwt"

// Supported signing algorithms. RFC 9449 section 4.2 admits asymmetric algorithms only. HS* is
// excluded because a MAC cannot prove possession of a private key. Operators can extend
// Service.AllowedSignAlgs for the long tail (ES512, ES256K).
const (
	AlgES256 = "ES256"
	AlgES384 = "ES384"
	AlgRS256 = "RS256"
	AlgPS256 = "PS256"
	AlgEdDSA = "EdDSA"
)

// DefaultAllowedAlgs is the set Service.New uses when AllowedSignAlgs is unset. EdDSA is included
// because browsers and mobile SDKs use it, even though RFC 9449 leaves it optional.
var DefaultAllowedAlgs = []string{AlgES256, AlgES384, AlgRS256, AlgPS256, AlgEdDSA}

// JWK is the minimal JSON Web Key the verifier needs: public members only. Private members are not
// parsed, so a malformed proof cannot steer the verifier into unexpected fields.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

// ProofHeader is the JOSE header of a DPoP proof JWT.
type ProofHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	JWK *JWK   `json:"jwk"`
}

// ProofClaims is the payload of a DPoP proof JWT. Field names mirror RFC
// 9449 section 4.2 exactly.
type ProofClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// Proof is a parsed and verified DPoP proof. Callers read the thumbprint, jti and nonce from it
// without re-parsing.
type Proof struct {
	Header     ProofHeader
	Claims     ProofClaims
	Thumbprint string // base64url(SHA-256(canonical JWK))
}

// VerifyParams are the per-request inputs of a proof check. htm and htu are compared against Method
// and URL, and AccessToken, when set, against ath.
type VerifyParams struct {
	// Method is the HTTP method of the request. It is compared with htm case-insensitively (RFC 9449
	// section 4.3).
	Method string

	// URL is the request URL. htu is compared after stripping the fragment and query from both sides
	// (RFC 9449 section 4.3).
	URL string

	// AccessToken, when set, requires the proof's ath claim to equal base64url(SHA-256(AccessToken)).
	// Token endpoints leave it empty.
	AccessToken string

	// Now is the reference time for iat / nonce expiry checks. Defaults to
	// time.Now().UTC() when zero.
	Now time.Time

	// RequireNonce forces the proof to carry a nonce the store accepts. A nonce that is present is
	// always verified, so a client cannot pass an arbitrary string.
	RequireNonce bool
}

// Sentinel errors. Handlers use errors.Is to map them to RFC 9449 wire responses:
// invalid_dpop_proof or use_dpop_nonce.
var (
	ErrMalformedProof   = errors.New("dpop: malformed proof JWT")
	ErrUnsupportedAlg   = errors.New("dpop: unsupported alg")
	ErrSignatureInvalid = errors.New("dpop: signature mismatch")
	ErrProofExpired     = errors.New("dpop: proof iat outside acceptance window")
	ErrMethodMismatch   = errors.New("dpop: htm does not match request method")
	ErrURIMismatch      = errors.New("dpop: htu does not match request URI")
	ErrATHMismatch      = errors.New("dpop: ath does not match access token hash")
	ErrATHRequired      = errors.New("dpop: proof missing ath claim")
	ErrNonceRequired    = errors.New("dpop: proof missing required nonce")
	ErrNonceInvalid     = errors.New("dpop: proof nonce rejected")
	ErrReplay           = errors.New("dpop: proof jti replay detected")
	ErrReplayStore      = errors.New("dpop: replay cache unavailable")
	ErrJKTMismatch      = errors.New("dpop: proof key thumbprint does not match cnf.jkt")
)

// ParseProof splits a compact JWT and parses its header and payload. The signature is not verified,
// so callers must use Service.Verify.
func ParseProof(token string) (ProofHeader, ProofClaims, []byte, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ProofHeader{}, ProofClaims{}, nil, nil, ErrMalformedProof
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ProofHeader{}, ProofClaims{}, nil, nil, fmt.Errorf("%w: header decode: %v", ErrMalformedProof, err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ProofHeader{}, ProofClaims{}, nil, nil, fmt.Errorf("%w: payload decode: %v", ErrMalformedProof, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ProofHeader{}, ProofClaims{}, nil, nil, fmt.Errorf("%w: signature decode: %v", ErrMalformedProof, err)
	}
	var hdr ProofHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return ProofHeader{}, ProofClaims{}, nil, nil, fmt.Errorf("%w: header parse: %v", ErrMalformedProof, err)
	}
	var claims ProofClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return ProofHeader{}, ProofClaims{}, nil, nil, fmt.Errorf("%w: payload parse: %v", ErrMalformedProof, err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	return hdr, claims, sig, signingInput, nil
}

// verifySignature dispatches to the per-algorithm verifier. The header alg is the source of truth;
// the caller has already checked the allow list.
func verifySignature(alg string, jwk *JWK, signingInput, sig []byte) error {
	if jwk == nil {
		return fmt.Errorf("%w: missing jwk", ErrMalformedProof)
	}
	switch alg {
	case AlgES256:
		return verifyECDSA(jwk, signingInput, sig, elliptic.P256(), sha256.New())
	case AlgES384:
		return verifyECDSA(jwk, signingInput, sig, elliptic.P384(), sha512.New384())
	case AlgRS256:
		return verifyRSA(jwk, signingInput, sig, crypto.SHA256, false)
	case AlgPS256:
		return verifyRSA(jwk, signingInput, sig, crypto.SHA256, true)
	case AlgEdDSA:
		return verifyEdDSA(jwk, signingInput, sig)
	default:
		return ErrUnsupportedAlg
	}
}

func verifyECDSA(jwk *JWK, signingInput, sig []byte, curve elliptic.Curve, h hash.Hash) error {
	if jwk.Kty != "EC" {
		return fmt.Errorf("%w: alg requires kty=EC", ErrMalformedProof)
	}
	if jwk.X == "" || jwk.Y == "" {
		return fmt.Errorf("%w: jwk missing x/y", ErrMalformedProof)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return fmt.Errorf("%w: jwk x decode", ErrMalformedProof)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return fmt.Errorf("%w: jwk y decode", ErrMalformedProof)
	}
	// The on-curve check uses crypto/ecdh (elliptic.IsOnCurve is deprecated since Go 1.21). It also
	// rejects the identity point.
	byteSize := (curve.Params().BitSize + 7) / 8
	uncompressed := make([]byte, 1+2*byteSize)
	uncompressed[0] = 0x04
	copy(uncompressed[1+byteSize-len(xBytes):], xBytes)
	copy(uncompressed[1+2*byteSize-len(yBytes):], yBytes)
	var ecdhCurve ecdh.Curve
	switch curve {
	case elliptic.P256():
		ecdhCurve = ecdh.P256()
	case elliptic.P384():
		ecdhCurve = ecdh.P384()
	default:
		return fmt.Errorf("%w: unsupported curve", ErrMalformedProof)
	}
	if _, err := ecdhCurve.NewPublicKey(uncompressed); err != nil {
		return fmt.Errorf("%w: jwk point off curve", ErrMalformedProof)
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
	// JOSE ECDSA signatures are fixed-length: R||S with R and S each
	// (curve order byte size) bytes. RFC 7515 section 3.4.
	if len(sig) != 2*byteSize {
		return fmt.Errorf("%w: signature length mismatch", ErrSignatureInvalid)
	}
	r := new(big.Int).SetBytes(sig[:byteSize])
	sVal := new(big.Int).SetBytes(sig[byteSize:])
	h.Write(signingInput)
	digest := h.Sum(nil)
	if !ecdsa.Verify(pub, digest, r, sVal) {
		return ErrSignatureInvalid
	}
	return nil
}

func verifyRSA(jwk *JWK, signingInput, sig []byte, hashAlg crypto.Hash, pss bool) error {
	if jwk.Kty != "RSA" {
		return fmt.Errorf("%w: alg requires kty=RSA", ErrMalformedProof)
	}
	if jwk.N == "" || jwk.E == "" {
		return fmt.Errorf("%w: jwk missing n/e", ErrMalformedProof)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return fmt.Errorf("%w: jwk n decode", ErrMalformedProof)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return fmt.Errorf("%w: jwk e decode", ErrMalformedProof)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return fmt.Errorf("%w: jwk n/e empty", ErrMalformedProof)
	}
	// RSA moduli must be at least 2048 bits, to block weak keys smuggled in by a client (RFC 7518
	// section 6.3.1).
	if len(nBytes)*8 < 2048 {
		return fmt.Errorf("%w: rsa modulus shorter than 2048 bits", ErrMalformedProof)
	}
	e := new(big.Int).SetBytes(eBytes).Int64()
	if e <= 0 || e > 1<<31-1 {
		return fmt.Errorf("%w: jwk e out of range", ErrMalformedProof)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e)}
	h := hashAlg.New()
	h.Write(signingInput)
	digest := h.Sum(nil)
	if pss {
		if err := rsa.VerifyPSS(pub, hashAlg, digest, sig, nil); err != nil {
			return ErrSignatureInvalid
		}
		return nil
	}
	if err := rsa.VerifyPKCS1v15(pub, hashAlg, digest, sig); err != nil {
		return ErrSignatureInvalid
	}
	return nil
}

func verifyEdDSA(jwk *JWK, signingInput, sig []byte) error {
	if jwk.Kty != "OKP" {
		return fmt.Errorf("%w: alg requires kty=OKP", ErrMalformedProof)
	}
	if jwk.Crv != "Ed25519" {
		return fmt.Errorf("%w: EdDSA requires crv=Ed25519", ErrMalformedProof)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return fmt.Errorf("%w: jwk x decode", ErrMalformedProof)
	}
	if len(xBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: ed25519 public key wrong length", ErrMalformedProof)
	}
	if !ed25519.Verify(ed25519.PublicKey(xBytes), signingInput, sig) {
		return ErrSignatureInvalid
	}
	return nil
}

// Thumbprint computes the RFC 7638 base64url(SHA-256(canonical JSON)). Key order is fixed by key
// type, and other algorithms are rejected.
func Thumbprint(jwk *JWK) (string, error) {
	if jwk == nil {
		return "", fmt.Errorf("%w: nil jwk", ErrMalformedProof)
	}
	var canonical string
	switch jwk.Kty {
	case "EC":
		if jwk.Crv == "" || jwk.X == "" || jwk.Y == "" {
			return "", fmt.Errorf("%w: EC jwk missing crv/x/y", ErrMalformedProof)
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, jwk.Crv, jwk.X, jwk.Y)
	case "RSA":
		if jwk.N == "" || jwk.E == "" {
			return "", fmt.Errorf("%w: RSA jwk missing n/e", ErrMalformedProof)
		}
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, jwk.E, jwk.N)
	case "OKP":
		if jwk.Crv == "" || jwk.X == "" {
			return "", fmt.Errorf("%w: OKP jwk missing crv/x", ErrMalformedProof)
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, jwk.Crv, jwk.X)
	default:
		return "", fmt.Errorf("%w: unsupported kty %q", ErrMalformedProof, jwk.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// canonicalURI returns the htu comparison form: scheme, host and path, with default ports and query
// and fragment removed (RFC 9449 section 4.3).
func canonicalURI(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("dpop: htu must be absolute (got %q)", rawURL)
	}
	host := parsed.Host
	// Strip default ports so http://foo:80/x and http://foo/x compare
	// equal (browsers normalize differently than server-side).
	switch {
	case strings.EqualFold(parsed.Scheme, "http") && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	case strings.EqualFold(parsed.Scheme, "https") && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	return strings.ToLower(parsed.Scheme) + "://" + host + path, nil
}
