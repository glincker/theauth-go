package mcpresource

import (
	"crypto"
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
	"sync"
	"time"
)

// dpop.go: RFC 9449 DPoP proof verification for the resource-server
// middleware. Mirror of the algorithm + check set implemented by
// internal/dpop in the AS, copied here verbatim because Go's module
// boundary prevents the mcpresource module (separate go.mod) from
// importing an internal/ package. This file is intentionally
// dependency-free: only Go stdlib so the mcpresource module honors the
// hard constraint that it may NOT pick up new go.mod entries.
//
// When the inbound access token carries an RFC 7800 cnf.jkt claim the
// validator REQUIRES the request to also carry a DPoP header and
// REQUIRES the proof key thumbprint to equal that cnf.jkt. A token
// without cnf.jkt is treated as a vanilla Bearer token; this preserves
// backward compatibility with deployments that have not enabled DPoP
// on the AS side.

// dpopProofTyp is the typ value mandated by RFC 9449 section 4.2.
const dpopProofTyp = "dpop+jwt"

// defaultDPoPAlgs is the algorithm set the validator accepts when the
// operator does not customize it via WithDPoPSignAlgs.
var defaultDPoPAlgs = []string{"ES256", "ES384", "RS256", "PS256", "EdDSA"}

// dpopJWK is the public-key material a proof header carries.
type dpopJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type dpopHeader struct {
	Typ string   `json:"typ"`
	Alg string   `json:"alg"`
	JWK *dpopJWK `json:"jwk"`
}

type dpopClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// dpopVerifier is the per-validator runtime that owns the allow list,
// the jti replay window, and the proof acceptance window.
type dpopVerifier struct {
	allowedAlgs  map[string]struct{}
	proofMaxAge  time.Duration
	jtiCap       int
	jtiSeen      map[string]time.Time
	jtiOrder     []string
	mu           sync.Mutex
	clockSkewMax time.Duration
}

func newDPoPVerifier(algs []string, maxAge, skew time.Duration, jtiCap int) *dpopVerifier {
	if len(algs) == 0 {
		algs = defaultDPoPAlgs
	}
	set := make(map[string]struct{}, len(algs))
	for _, a := range algs {
		set[a] = struct{}{}
	}
	if maxAge <= 0 {
		maxAge = 60 * time.Second
	}
	if jtiCap <= 0 {
		jtiCap = 4096
	}
	return &dpopVerifier{
		allowedAlgs:  set,
		proofMaxAge:  maxAge,
		clockSkewMax: skew,
		jtiCap:       jtiCap,
		jtiSeen:      make(map[string]time.Time, jtiCap),
		jtiOrder:     make([]string, 0, jtiCap),
	}
}

// dpopVerifyParams are the inputs the resource server provides for one
// inbound request.
type dpopVerifyParams struct {
	method      string
	url         string
	accessToken string
	requiredJKT string
	now         time.Time
}

// verifyAndBind runs every RFC 9449 section 4.3 step against the
// inbound proof and confirms the proof key thumbprint matches the
// supplied cnf.jkt. Returns the canonical thumbprint on success.
func (v *dpopVerifier) verifyAndBind(proofJWT string, params dpopVerifyParams) (string, error) {
	parts := strings.Split(proofJWT, ".")
	if len(parts) != 3 {
		return "", errDPoPMalformed
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("%w: header decode: %v", errDPoPMalformed, err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: payload decode: %v", errDPoPMalformed, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("%w: signature decode: %v", errDPoPMalformed, err)
	}
	var hdr dpopHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return "", fmt.Errorf("%w: header parse", errDPoPMalformed)
	}
	var claims dpopClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", fmt.Errorf("%w: payload parse", errDPoPMalformed)
	}
	if hdr.Typ != dpopProofTyp {
		return "", fmt.Errorf("%w: wrong typ", errDPoPMalformed)
	}
	if _, ok := v.allowedAlgs[hdr.Alg]; !ok {
		return "", fmt.Errorf("%w: alg %q not allowed", errDPoPMalformed, hdr.Alg)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if err := dpopVerifySig(hdr.Alg, hdr.JWK, signingInput, sig); err != nil {
		return "", err
	}
	if !strings.EqualFold(claims.HTM, params.method) {
		return "", errDPoPMethodMismatch
	}
	wantURI, err := canonicalDPoPURI(params.url)
	if err != nil {
		return "", err
	}
	gotURI, err := canonicalDPoPURI(claims.HTU)
	if err != nil {
		return "", errDPoPURIMismatch
	}
	if gotURI != wantURI {
		return "", errDPoPURIMismatch
	}
	now := params.now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if claims.IAT == 0 {
		return "", errDPoPProofExpired
	}
	iat := time.Unix(claims.IAT, 0)
	delta := now.Sub(iat)
	if delta < 0 {
		delta = -delta
	}
	if delta > v.proofMaxAge+v.clockSkewMax {
		return "", errDPoPProofExpired
	}
	if claims.JTI == "" {
		return "", fmt.Errorf("%w: missing jti", errDPoPMalformed)
	}
	if !v.rememberJTI(claims.JTI, iat.Add(v.proofMaxAge)) {
		return "", errDPoPReplay
	}
	// ath REQUIRED on resource-server proofs (RFC 9449 section 4.2).
	if claims.ATH == "" {
		return "", errDPoPATHRequired
	}
	wantATH := dpopAccessTokenHash(params.accessToken)
	if claims.ATH != wantATH {
		return "", errDPoPATHMismatch
	}
	thumb, err := dpopThumbprint(hdr.JWK)
	if err != nil {
		return "", err
	}
	if params.requiredJKT != "" && thumb != params.requiredJKT {
		return "", errDPoPJKTMismatch
	}
	return thumb, nil
}

func (v *dpopVerifier) rememberJTI(jti string, expiresAt time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := time.Now()
	if exp, ok := v.jtiSeen[jti]; ok && now.Before(exp) {
		return false
	}
	// Lazy sweep: trim front entries whose deadline has passed.
	for len(v.jtiOrder) > 0 {
		head := v.jtiOrder[0]
		if exp, ok := v.jtiSeen[head]; ok && now.Before(exp) {
			break
		}
		v.jtiOrder = v.jtiOrder[1:]
		delete(v.jtiSeen, head)
	}
	for len(v.jtiOrder) >= v.jtiCap {
		head := v.jtiOrder[0]
		v.jtiOrder = v.jtiOrder[1:]
		delete(v.jtiSeen, head)
	}
	v.jtiSeen[jti] = expiresAt
	v.jtiOrder = append(v.jtiOrder, jti)
	return true
}

func dpopAccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// dpopThumbprint computes the RFC 7638 base64url SHA-256 thumbprint of
// jwk.
func dpopThumbprint(jwk *dpopJWK) (string, error) {
	if jwk == nil {
		return "", fmt.Errorf("%w: nil jwk", errDPoPMalformed)
	}
	var canonical string
	switch jwk.Kty {
	case "EC":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, jwk.Crv, jwk.X, jwk.Y)
	case "RSA":
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, jwk.E, jwk.N)
	case "OKP":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, jwk.Crv, jwk.X)
	default:
		return "", fmt.Errorf("%w: unsupported kty %q", errDPoPMalformed, jwk.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func dpopVerifySig(alg string, jwk *dpopJWK, signingInput, sig []byte) error {
	if jwk == nil {
		return fmt.Errorf("%w: missing jwk", errDPoPMalformed)
	}
	switch alg {
	case "ES256":
		return dpopVerifyECDSA(jwk, signingInput, sig, elliptic.P256(), sha256.New())
	case "ES384":
		return dpopVerifyECDSA(jwk, signingInput, sig, elliptic.P384(), sha512.New384())
	case "RS256":
		return dpopVerifyRSA(jwk, signingInput, sig, crypto.SHA256, false)
	case "PS256":
		return dpopVerifyRSA(jwk, signingInput, sig, crypto.SHA256, true)
	case "EdDSA":
		return dpopVerifyEdDSA(jwk, signingInput, sig)
	default:
		return fmt.Errorf("%w: alg %q", errDPoPMalformed, alg)
	}
}

func dpopVerifyECDSA(jwk *dpopJWK, signingInput, sig []byte, curve elliptic.Curve, h hash.Hash) error {
	if jwk.Kty != "EC" {
		return fmt.Errorf("%w: alg needs EC", errDPoPMalformed)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return fmt.Errorf("%w: jwk x decode", errDPoPMalformed)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return fmt.Errorf("%w: jwk y decode", errDPoPMalformed)
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
	if !curve.IsOnCurve(pub.X, pub.Y) {
		return fmt.Errorf("%w: point off curve", errDPoPMalformed)
	}
	bitSize := curve.Params().BitSize
	byteSize := (bitSize + 7) / 8
	if len(sig) != 2*byteSize {
		return errDPoPSignature
	}
	r := new(big.Int).SetBytes(sig[:byteSize])
	sVal := new(big.Int).SetBytes(sig[byteSize:])
	h.Write(signingInput)
	digest := h.Sum(nil)
	if !ecdsa.Verify(pub, digest, r, sVal) {
		return errDPoPSignature
	}
	return nil
}

func dpopVerifyRSA(jwk *dpopJWK, signingInput, sig []byte, hashAlg crypto.Hash, pss bool) error {
	if jwk.Kty != "RSA" {
		return fmt.Errorf("%w: alg needs RSA", errDPoPMalformed)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return fmt.Errorf("%w: jwk n decode", errDPoPMalformed)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return fmt.Errorf("%w: jwk e decode", errDPoPMalformed)
	}
	if len(nBytes)*8 < 2048 {
		return fmt.Errorf("%w: rsa modulus shorter than 2048 bits", errDPoPMalformed)
	}
	e := new(big.Int).SetBytes(eBytes).Int64()
	if e <= 0 {
		return fmt.Errorf("%w: jwk e out of range", errDPoPMalformed)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e)}
	h := hashAlg.New()
	h.Write(signingInput)
	digest := h.Sum(nil)
	if pss {
		if err := rsa.VerifyPSS(pub, hashAlg, digest, sig, nil); err != nil {
			return errDPoPSignature
		}
		return nil
	}
	if err := rsa.VerifyPKCS1v15(pub, hashAlg, digest, sig); err != nil {
		return errDPoPSignature
	}
	return nil
}

func dpopVerifyEdDSA(jwk *dpopJWK, signingInput, sig []byte) error {
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return fmt.Errorf("%w: alg needs OKP/Ed25519", errDPoPMalformed)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return fmt.Errorf("%w: jwk x decode", errDPoPMalformed)
	}
	if len(xBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: ed25519 key wrong length", errDPoPMalformed)
	}
	if !ed25519.Verify(ed25519.PublicKey(xBytes), signingInput, sig) {
		return errDPoPSignature
	}
	return nil
}

func canonicalDPoPURI(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("mcpresource: htu must be absolute")
	}
	host := parsed.Host
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

var (
	errDPoPMalformed      = errors.New("mcpresource: malformed DPoP proof")
	errDPoPSignature      = errors.New("mcpresource: DPoP signature mismatch")
	errDPoPMethodMismatch = errors.New("mcpresource: DPoP htm does not match request method")
	errDPoPURIMismatch    = errors.New("mcpresource: DPoP htu does not match request URI")
	errDPoPATHRequired    = errors.New("mcpresource: DPoP proof missing ath")
	errDPoPATHMismatch    = errors.New("mcpresource: DPoP ath does not match access token")
	errDPoPProofExpired   = errors.New("mcpresource: DPoP proof iat outside acceptance window")
	errDPoPReplay         = errors.New("mcpresource: DPoP proof jti replay detected")
	errDPoPJKTMismatch    = errors.New("mcpresource: DPoP key thumbprint does not match cnf.jkt")
	errDPoPMissingHeader  = errors.New("mcpresource: DPoP-bound token requires DPoP header")
)
