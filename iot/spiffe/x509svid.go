package spiffe

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"time"
)

// Failure codes, shared with the TypeScript implementation.
const (
	CodeMalformed         = "malformed"
	CodeNoURISAN          = "no_uri_san"
	CodeMultipleURISANs   = "multiple_uri_sans"
	CodeInvalidSPIFFEID   = "invalid_spiffe_id"
	CodeUntrustedDomain   = "untrusted_domain"
	CodeNotYetValid       = "not_yet_valid"
	CodeExpired           = "expired"
	CodeLifetimeTooLong   = "lifetime_too_long"
	CodeCALeaf            = "ca_leaf"
	CodeKeyUsage          = "key_usage"
	CodeExtension         = "extension"
	CodeUntrustedChain    = "untrusted_chain"
	CodeWrongAudience     = "wrong_audience"
	CodeUnsupportedAlg    = "unsupported_alg"
	CodeBadSignature      = "bad_signature"
	CodeMissingClaim      = "missing_claim"
	CodeUnknownWorkload   = "unknown_workload"
	CodePrincipalInactive = "principal_inactive"
)

// Error is a refused SVID. Code is stable, Reason is for logs and must not be echoed to the caller.
type Error struct {
	Code   string
	Reason string
}

func (e *Error) Error() string { return e.Code + ": " + e.Reason }

func fail(code, reason string) *Error { return &Error{Code: code, Reason: reason} }

// X509Options tunes X.509-SVID validation. The zero value is valid.
type X509Options struct {
	// Now defaults to time.Now().
	Now time.Time
	// ClockSkew is allowed on every validity period. Default 30s. Set NoSkew for zero.
	ClockSkew time.Duration
	NoSkew    bool
	// MaxLifetime refuses an SVID whose NotAfter minus NotBefore is longer. Zero means no limit.
	MaxLifetime time.Duration
	// MaxChain is the most certificates in the presented chain, leaf included. Default 6.
	MaxChain int
}

// X509Identity is a verified X.509-SVID.
type X509Identity struct {
	ID        ID
	NotBefore time.Time
	NotAfter  time.Time
	// Thumbprint is x5t#S256 (RFC 8705 section 3.1): base64url SHA-256 of the DER leaf.
	Thumbprint string
}

var (
	oidKeyUsage   = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSAN        = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidEKU        = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidAnyEKU     = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
)

func hasExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	_, ok := extensionOf(c, oid)
	return ok
}

func extensionOf(c *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

// sanURIs reads the URI GeneralNames (context tag 6) of the SAN extension straight from the DER, so a
// URI the standard library would reject still reaches the SPIFFE ID check (RFC 5280 section 4.2.1.6).
func sanURIs(c *x509.Certificate) (uris []string, critical bool, err error) {
	ext, ok := extensionOf(c, oidSAN)
	if !ok {
		return nil, false, nil
	}
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(ext.Value, &seq); err != nil || len(rest) > 0 || seq.Tag != asn1.TagSequence {
		return nil, ext.Critical, asn1.StructuralError{Msg: "bad SAN"}
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var name asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &name); err != nil {
			return nil, ext.Critical, err
		}
		if name.Class == asn1.ClassContextSpecific && name.Tag == 6 && !name.IsCompound {
			uris = append(uris, string(name.Bytes))
		}
	}
	return uris, ext.Critical, nil
}

// VerifyX509 validates a presented chain (leaf first, then intermediates) against the bundle of the
// leaf's trust domain, following X509-SVID.md: one URI SAN that is a SPIFFE ID with a path (section
// 2, 3.1), cA false (4.1), key usage present, critical, digitalSignature and no keyCertSign or
// cRLSign (4.3), path validation per RFC 5280 (5.1). Beyond the spec the chain must end at a CA of
// the leaf's own trust domain, an unknown critical extension is refused, and extended key usage,
// when present, must allow clientAuth. The caller must know the peer holds the leaf key.
func VerifyX509(ctx context.Context, chain []*x509.Certificate, store *Store, opts X509Options) (*X509Identity, *Error) {
	maxChain := opts.MaxChain
	if maxChain == 0 {
		maxChain = 6
	}
	if len(chain) == 0 || len(chain) > maxChain {
		return nil, fail(CodeMalformed, "bad certificate chain length")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := opts.ClockSkew
	if skew == 0 && !opts.NoSkew {
		skew = 30 * time.Second
	}
	leaf := chain[0]
	id, ferr := checkLeaf(leaf, now, skew, opts.MaxLifetime)
	if ferr != nil {
		return nil, ferr
	}
	bundle := store.Get(ctx, id.TrustDomain)
	if bundle == nil {
		return nil, fail(CodeUntrustedDomain, "no trust bundle for this trust domain")
	}
	inWindow := func(c *x509.Certificate) bool {
		return !now.Add(skew).Before(c.NotBefore) && !now.Add(-skew).After(c.NotAfter)
	}
	for _, c := range chain[1:] {
		if !inWindow(c) {
			return nil, fail(CodeUntrustedChain, "an intermediate is outside its validity period")
		}
	}
	var anchors []*x509.Certificate
	for _, a := range bundle.X509Authorities {
		if inWindow(a) {
			anchors = append(anchors, a)
		}
	}
	if reason := verifyChain(chain, anchors); reason != "" {
		return nil, fail(CodeUntrustedChain, reason)
	}
	sum := sha256.Sum256(leaf.Raw)
	return &X509Identity{
		ID:         id,
		NotBefore:  leaf.NotBefore,
		NotAfter:   leaf.NotAfter,
		Thumbprint: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

func checkLeaf(leaf *x509.Certificate, now time.Time, skew, maxLife time.Duration) (ID, *Error) {
	uris, sanCritical, err := sanURIs(leaf)
	if err != nil {
		return ID{}, fail(CodeMalformed, "certificate extension could not be read")
	}
	if len(uris) == 0 {
		return ID{}, fail(CodeNoURISAN, "SVID has no URI SAN")
	}
	if len(uris) > 1 {
		return ID{}, fail(CodeMultipleURISANs, "SVID has more than one URI SAN")
	}
	id, perr := ParseID(uris[0])
	if perr != nil {
		return ID{}, fail(CodeInvalidSPIFFEID, perr.Error())
	}
	if id.Path == "" {
		return ID{}, fail(CodeInvalidSPIFFEID, "leaf SPIFFE ID needs a path")
	}
	if len(leaf.RawSubject) == 2 && leaf.RawSubject[0] == 0x30 && leaf.RawSubject[1] == 0 && !sanCritical {
		return ID{}, fail(CodeExtension, "URI SAN must be critical when the Subject is empty")
	}
	if len(leaf.UnhandledCriticalExtensions) > 0 {
		return ID{}, fail(CodeExtension, "unknown critical extension "+leaf.UnhandledCriticalExtensions[0].String())
	}
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return ID{}, fail(CodeCALeaf, "leaf has the CA flag set")
	}
	ku, ok := extensionOf(leaf, oidKeyUsage)
	switch {
	case !ok:
		return ID{}, fail(CodeKeyUsage, "key usage extension is missing")
	case !ku.Critical:
		return ID{}, fail(CodeKeyUsage, "key usage extension is not critical")
	case leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0:
		return ID{}, fail(CodeKeyUsage, "leaf lacks digitalSignature")
	case leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0:
		return ID{}, fail(CodeKeyUsage, "leaf has keyCertSign or cRLSign")
	}
	if hasExtension(leaf, oidEKU) && !allowsClientAuth(leaf) {
		return ID{}, fail(CodeKeyUsage, "extended key usage does not allow clientAuth")
	}
	if now.Add(skew).Before(leaf.NotBefore) {
		return ID{}, fail(CodeNotYetValid, "SVID is not valid yet")
	}
	if now.Add(-skew).After(leaf.NotAfter) {
		return ID{}, fail(CodeExpired, "SVID has expired")
	}
	if maxLife > 0 && leaf.NotAfter.Sub(leaf.NotBefore) > maxLife {
		return ID{}, fail(CodeLifetimeTooLong, "SVID lifetime is longer than allowed")
	}
	return id, nil
}

func allowsClientAuth(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	for _, u := range c.UnknownExtKeyUsage {
		if u.Equal(oidClientAuth) || u.Equal(oidAnyEKU) {
			return true
		}
	}
	return false
}

// verifyChain checks each certificate is signed by the next, every issuer is a CA that may sign
// certificates and respects pathLenConstraint, and the last certificate is an anchor or is signed by
// one. Validity is checked by the caller. It returns a reason, or "" when the chain is good.
func verifyChain(chain, anchors []*x509.Certificate) string {
	for i := 1; i < len(chain); i++ {
		iss := chain[i]
		if !iss.BasicConstraintsValid || !iss.IsCA || (hasExtension(iss, oidKeyUsage) && iss.KeyUsage&x509.KeyUsageCertSign == 0) {
			return "an issuer in the chain is not a CA"
		}
		// Intermediates between this issuer and the leaf: i - 1.
		// MaxPathLen is -1 when the constraint is absent.
		if iss.MaxPathLen >= 0 && iss.MaxPathLen < i-1 {
			return "path length constraint exceeded"
		}
	}
	for i := 0; i < len(chain)-1; i++ {
		if string(chain[i].RawIssuer) != string(chain[i+1].RawSubject) {
			return "certificate chain is not ordered leaf first"
		}
		if chain[i].CheckSignatureFrom(chain[i+1]) != nil {
			return "a certificate signature in the chain is invalid"
		}
	}
	last := chain[len(chain)-1]
	for _, a := range anchors {
		if a.Equal(last) {
			return ""
		}
		if string(a.RawSubject) == string(last.RawIssuer) && last.CheckSignatureFrom(a) == nil {
			return ""
		}
	}
	return "chain does not end at a trusted root"
}
