package attest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"time"
)

// This file ports the TypeScript X.509 reader and its reduced RFC 5280 chain check. It does not
// use crypto/x509 to parse or verify chains: Go's verifier enforces extended key usage, name
// constraints and critical extension rules that real attestation chains do not satisfy, and the
// goal is the same accept and refuse decisions as the TypeScript verifiers. The standard library
// is used for the signature math itself.

const (
	oidBasicConstraints  = "2.5.29.19"
	oidKeyUsage          = "2.5.29.15"
	oidSerialNumberAttr  = "2.5.4.5"
	oidRSAEncryption     = "1.2.840.113549.1.1.1"
	oidECPublicKey       = "1.2.840.10045.2.1"
	oidCurveP256         = "1.2.840.10045.3.1.7"
	oidCurveP384         = "1.3.132.0.34"
	oidCurveP521         = "1.3.132.0.35"
	maxCertTextBytes     = 1 << 20
	invalidBase64Message = "Invalid character"
)

type x509Extension struct {
	critical bool
	value    []byte
}

// certificate is a parsed X.509 certificate.
type certificate struct {
	der []byte
	tbs []byte
	// serialHex is lowercase hex without leading zeros, the form Google's revocation list uses.
	serialHex string
	issuer    []byte
	subject   []byte
	notBefore time.Time
	notAfter  time.Time
	spki      []byte
	sigAlg    string
	// tbsSigAlg is the `signature` AlgorithmIdentifier inside the TBS, which must equal the outer one.
	tbsSigAlg           string
	signature           []byte
	extensions          map[string]x509Extension
	subjectSerialNumber string
	hasSubjectSerial    bool
}

func parseTime(t tlv) (time.Time, error) {
	s := string(t.content)
	var digits string
	var year int
	switch {
	case isUniversal(t, tagUTCTime):
		if len(s) != 13 || s[12] != 'Z' || !allDigits(s[:12]) {
			return time.Time{}, derErr("bad UTCTime")
		}
		digits = s[:12]
		yy := atoi(digits[0:2])
		if yy >= 50 {
			year = 1900 + yy
		} else {
			year = 2000 + yy
		}
		digits = digits[2:]
	case isUniversal(t, tagGenTime):
		if len(s) != 15 || s[14] != 'Z' || !allDigits(s[:14]) {
			return time.Time{}, derErr("bad GeneralizedTime")
		}
		year = atoi(s[0:4])
		digits = s[4:14]
	default:
		return time.Time{}, derErr("bad time type")
	}
	return time.Date(year, time.Month(atoi(digits[0:2])), atoi(digits[2:4]), atoi(digits[4:6]),
		atoi(digits[6:8]), atoi(digits[8:10]), 0, time.UTC), nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// nameSerialNumber returns the serialNumber attribute (OID 2.5.4.5) of a Name, if any.
func nameSerialNumber(name tlv) (string, bool, error) {
	rdns, err := children(name)
	if err != nil {
		return "", false, err
	}
	for _, rdn := range rdns {
		atvs, err := children(rdn)
		if err != nil {
			return "", false, err
		}
		for _, atv := range atvs {
			parts, err := children(atv)
			if err != nil {
				return "", false, err
			}
			if len(parts) < 2 {
				continue
			}
			oid, err := oidOf(parts[0])
			if err != nil {
				return "", false, err
			}
			if oid == oidSerialNumberAttr {
				s, err := stringOf(parts[1])
				return s, true, err
			}
		}
	}
	return "", false, nil
}

func hexOfInteger(t tlv) string {
	c := t.content
	for len(c) > 1 && c[0] == 0 {
		c = c[1:]
	}
	h := hex.EncodeToString(c)
	for len(h) > 1 && h[0] == '0' {
		h = h[1:]
	}
	if h == "" {
		return "0"
	}
	return h
}

func algOf(t tlv) (string, error) {
	kids, err := children(t)
	if err != nil {
		return "", err
	}
	if len(kids) == 0 {
		return "", derErr("bad AlgorithmIdentifier")
	}
	return oidOf(kids[0])
}

// parseCertificate parses an X.509 certificate (RFC 5280 section 4.1).
func parseCertificate(der []byte) (*certificate, error) {
	cert, err := parseOne(der)
	if err != nil {
		return nil, err
	}
	top, err := children(cert)
	if err != nil {
		return nil, err
	}
	if len(top) != 3 {
		return nil, derErr("bad certificate")
	}
	tbsT, algT, sigT := top[0], top[1], top[2]
	fields, err := children(tbsT)
	if err != nil {
		return nil, err
	}
	i := 0
	if len(fields) > 0 && fields[0].cls == 2 && fields[0].tag == 0 {
		i++ // explicit version
	}
	if len(fields) < i+6 {
		return nil, derErr("short TBSCertificate")
	}
	serial, tbsAlg, issuer, validity, subject, spki := fields[i], fields[i+1], fields[i+2], fields[i+3], fields[i+4], fields[i+5]
	i += 6
	vk, err := children(validity)
	if err != nil {
		return nil, err
	}
	if len(vk) < 2 {
		return nil, derErr("bad validity")
	}
	extensions := map[string]x509Extension{}
	for _, f := range fields[i:] {
		if f.cls != 2 || f.tag != 3 {
			continue
		}
		fk, err := children(f)
		if err != nil {
			return nil, err
		}
		if len(fk) == 0 {
			return nil, derErr("bad extensions")
		}
		exts, err := children(fk[0])
		if err != nil {
			return nil, err
		}
		for _, ext := range exts {
			parts, err := children(ext)
			if err != nil {
				return nil, err
			}
			oid := ""
			if len(parts) > 0 {
				if oid, err = oidOf(parts[0]); err != nil {
					return nil, err
				}
			}
			if len(parts) == 0 {
				return nil, derErr("bad extension")
			}
			last := parts[len(parts)-1]
			if !isUniversal(last, tagOctetString) || len(parts) < 2 || len(parts) > 3 {
				return nil, derErr("bad extension")
			}
			critical := false
			if len(parts) == 3 {
				if critical, err = boolOf(parts[1]); err != nil {
					return nil, err
				}
			}
			if _, dup := extensions[oid]; dup {
				return nil, derErr("duplicate extension")
			}
			extensions[oid] = x509Extension{critical: critical, value: last.content}
		}
	}
	notBefore, err := parseTime(vk[0])
	if err != nil {
		return nil, err
	}
	notAfter, err := parseTime(vk[1])
	if err != nil {
		return nil, err
	}
	sigAlg, err := algOf(algT)
	if err != nil {
		return nil, err
	}
	tbsSigAlg, err := algOf(tbsAlg)
	if err != nil {
		return nil, err
	}
	sig, err := bitStringBytes(sigT)
	if err != nil {
		return nil, err
	}
	c := &certificate{
		der: der, tbs: tbsT.raw, serialHex: hexOfInteger(serial), issuer: issuer.raw, subject: subject.raw,
		notBefore: notBefore, notAfter: notAfter, spki: spki.raw, sigAlg: sigAlg, tbsSigAlg: tbsSigAlg,
		signature: sig, extensions: extensions,
	}
	sn, has, err := nameSerialNumber(subject)
	if err != nil {
		return nil, err
	}
	c.subjectSerialNumber, c.hasSubjectSerial = sn, has
	return c, nil
}

// decodeBase64 decodes standard or URL alphabet base64 with optional padding, like the
// TypeScript fromBase64Url followed by atob: ASCII whitespace is ignored and a length of 1 mod 4
// is refused.
func decodeBase64(s string) ([]byte, error) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case ' ', '\t', '\n', '\f', '\r':
		case '-':
			b.WriteByte('+')
		case '_':
			b.WriteByte('/')
		default:
			b.WriteByte(c)
		}
	}
	t := b.String()
	for len(t)%4 != 0 {
		t += "="
	}
	out, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		return nil, reasonErr(invalidBase64Message)
	}
	return out, nil
}

// certBytesFromText turns a PEM block or base64 DER into bytes. It accepts one certificate.
func certBytesFromText(text string) ([]byte, error) {
	if len(text) > maxCertTextBytes {
		return nil, reasonErr(invalidBase64Message)
	}
	body := strings.ReplaceAll(text, "-----BEGIN CERTIFICATE-----", "")
	body = strings.ReplaceAll(body, "-----END CERTIFICATE-----", "")
	return decodeBase64(body)
}

func parseCertText(text string) (*certificate, error) {
	der, err := certBytesFromText(text)
	if err != nil {
		return nil, err
	}
	return parseCertificate(der)
}

type sigAlgorithm struct {
	rsa  bool
	hash crypto.Hash
}

var sigAlgorithms = map[string]sigAlgorithm{
	"1.2.840.113549.1.1.11": {true, crypto.SHA256},
	"1.2.840.113549.1.1.12": {true, crypto.SHA384},
	"1.2.840.113549.1.1.13": {true, crypto.SHA512},
	"1.2.840.10045.4.3.2":   {false, crypto.SHA256},
	"1.2.840.10045.4.3.3":   {false, crypto.SHA384},
	"1.2.840.10045.4.3.4":   {false, crypto.SHA512},
}

var curveSizes = map[string]int{oidCurveP256: 32, oidCurveP384: 48, oidCurveP521: 66}

func hashBytes(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA256:
		s := sha256.Sum256(data)
		return s[:]
	case crypto.SHA384:
		s := sha512.Sum384(data)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:]
	}
	return nil
}

// ecdsaDERToInts reads an ECDSA-Sig-Value (RFC 3279 section 2.2.3). Like the TypeScript code it
// tolerates redundant leading zeros and refuses values wider than the curve.
func ecdsaDERToInts(der []byte, size int) (*big.Int, *big.Int, error) {
	seq, err := parseOne(der)
	if err != nil {
		return nil, nil, err
	}
	kids, err := children(seq)
	if err != nil {
		return nil, nil, err
	}
	if len(kids) < 2 {
		return nil, nil, derErr("bad ECDSA signature")
	}
	conv := func(t tlv) (*big.Int, error) {
		c := t.content
		for len(c) > size && c[0] == 0 {
			c = c[1:]
		}
		if len(c) > size {
			return nil, derErr("ECDSA value too long")
		}
		return new(big.Int).SetBytes(c), nil
	}
	r, err := conv(kids[0])
	if err != nil {
		return nil, nil, err
	}
	s, err := conv(kids[1])
	if err != nil {
		return nil, nil, err
	}
	return r, s, nil
}

type spkiParts struct {
	alg   string
	curve string
}

// spkiInfo returns the algorithm and curve parameter of a SubjectPublicKeyInfo.
func spkiInfo(spki []byte) (spkiParts, error) {
	top, err := parseOne(spki)
	if err != nil {
		return spkiParts{}, err
	}
	kids, err := children(top)
	if err != nil {
		return spkiParts{}, err
	}
	if len(kids) == 0 {
		return spkiParts{}, derErr("bad SubjectPublicKeyInfo")
	}
	alg, err := children(kids[0])
	if err != nil {
		return spkiParts{}, err
	}
	if len(alg) == 0 {
		return spkiParts{}, derErr("bad SubjectPublicKeyInfo")
	}
	oid, err := oidOf(alg[0])
	if err != nil {
		return spkiParts{}, err
	}
	out := spkiParts{alg: oid}
	if len(alg) > 1 && isUniversal(alg[1], tagOID) {
		if out.curve, err = oidOf(alg[1]); err != nil {
			return spkiParts{}, err
		}
	}
	return out, nil
}

// verifyCertSignature is true when the issuer key verifies the signature on cert. SHA-1 and
// unknown algorithms are refused.
func verifyCertSignature(cert *certificate, issuerSPKI []byte) bool {
	alg, ok := sigAlgorithms[cert.sigAlg]
	if !ok || cert.sigAlg != cert.tbsSigAlg {
		return false
	}
	info, err := spkiInfo(issuerSPKI)
	if err != nil {
		return false
	}
	pub, err := x509.ParsePKIXPublicKey(issuerSPKI)
	if err != nil {
		return false
	}
	digest := hashBytes(alg.hash, cert.tbs)
	if alg.rsa {
		key, ok := pub.(*rsa.PublicKey)
		if !ok || info.alg != oidRSAEncryption {
			return false
		}
		return rsa.VerifyPKCS1v15(key, alg.hash, digest, cert.signature) == nil
	}
	size, known := curveSizes[info.curve]
	key, ok := pub.(*ecdsa.PublicKey)
	if info.alg != oidECPublicKey || !known || !ok {
		return false
	}
	r, s, err := ecdsaDERToInts(cert.signature, size)
	if err != nil {
		return false
	}
	return ecdsa.Verify(key, digest, r, s)
}

type basicConstraintsInfo struct {
	ca         bool
	pathLen    int64
	hasPathLen bool
}

func basicConstraintsOf(cert *certificate) (*basicConstraintsInfo, error) {
	ext, ok := cert.extensions[oidBasicConstraints]
	if !ok {
		return nil, nil
	}
	top, err := parseOne(ext.value)
	if err != nil {
		return nil, err
	}
	kids, err := children(top)
	if err != nil {
		return nil, err
	}
	bc := &basicConstraintsInfo{}
	for _, c := range kids {
		switch {
		case isUniversal(c, tagBoolean):
			if bc.ca, err = boolOf(c); err != nil {
				return nil, err
			}
		case isUniversal(c, tagInteger):
			if bc.pathLen, err = intOf(c); err != nil {
				return nil, err
			}
			bc.hasPathLen = true
		}
	}
	return bc, nil
}

func mayCertSign(cert *certificate) (bool, error) {
	ext, ok := cert.extensions[oidKeyUsage]
	if !ok {
		return true, nil
	}
	top, err := parseOne(ext.value)
	if err != nil {
		return false, err
	}
	// keyCertSign is bit 5, the 0x04 bit of the first value octet (after the unused-bits octet).
	var b byte
	if len(top.content) > 1 {
		b = top.content[1]
	}
	return b&0x04 != 0, nil
}

type chainResult struct {
	ok     bool
	anchor *certificate
	reason string
}

type chainOptions struct {
	now time.Time
	// skipValidity skips the validity period of chain certificates. Anchors are never time checked.
	skipValidity bool
}

// verifyChain validates chain (leaf first) up to one of anchors (RFC 5280 section 6.1, reduced):
// each certificate is signed by the next, every issuer is a CA that may sign certificates and
// respects pathLenConstraint, validity covers now, and the last certificate is an anchor or is
// signed by one. A malformed extension in the chain is returned as an error.
func verifyChain(chain, anchors []*certificate, opts chainOptions) (chainResult, error) {
	fail := func(reason string) (chainResult, error) { return chainResult{reason: reason}, nil }
	if len(chain) == 0 {
		return fail("Certificate chain is empty")
	}
	if !opts.skipValidity {
		for _, c := range chain {
			if opts.now.Before(c.notBefore) || opts.now.After(c.notAfter) {
				return fail("A certificate in the chain is outside its validity period")
			}
		}
	}
	for i := 1; i < len(chain); i++ {
		issuer := chain[i]
		bc, err := basicConstraintsOf(issuer)
		if err != nil {
			return chainResult{}, err
		}
		if bc == nil || !bc.ca {
			return fail("An issuer in the chain is not a CA")
		}
		may, err := mayCertSign(issuer)
		if err != nil {
			return chainResult{}, err
		}
		if !may {
			return fail("An issuer in the chain is not a CA")
		}
		// Intermediates between this issuer and the leaf: i - 1.
		if bc.hasPathLen && bc.pathLen < int64(i-1) {
			return fail("Path length constraint exceeded")
		}
	}
	for i := 0; i < len(chain)-1; i++ {
		cert, issuer := chain[i], chain[i+1]
		if !bytes.Equal(cert.issuer, issuer.subject) {
			return fail("Certificate chain is not ordered leaf first")
		}
		if !verifyCertSignature(cert, issuer.spki) {
			return fail("A certificate signature in the chain is invalid")
		}
	}
	last := chain[len(chain)-1]
	for _, anchor := range anchors {
		if bytes.Equal(anchor.der, last.der) {
			return chainResult{ok: true, anchor: anchor}, nil
		}
		if bytes.Equal(anchor.subject, last.issuer) && verifyCertSignature(last, anchor.spki) {
			return chainResult{ok: true, anchor: anchor}, nil
		}
	}
	return fail("Chain does not end at a trusted root")
}

func parseAnchors(texts []string) ([]*certificate, error) {
	out := make([]*certificate, 0, len(texts))
	for _, t := range texts {
		c, err := parseCertText(t)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
