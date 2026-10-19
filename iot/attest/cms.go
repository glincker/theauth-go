package attest

// cms.go is the small CMS (RFC 5652) SignedData reader behind the App Attest receipt check: one signer,
// EC signatures, with or without signed attributes. Ported from apple-receipt.ts.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
)

const (
	oidSignedData    = "1.2.840.113549.1.7.2"
	oidCMSData       = "1.2.840.113549.1.7.1"
	oidMessageDigest = "1.2.840.113549.1.9.4"
	oidContentType   = "1.2.840.113549.1.9.3"
)

var cmsDigests = map[string]crypto.Hash{
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
}

// cmsECSignatures maps a signature algorithm OID to its hash. Zero means "use the digest algorithm"
// (id-ecPublicKey as the signature algorithm, RFC 5753).
var cmsECSignatures = map[string]crypto.Hash{
	"1.2.840.10045.4.3.2": crypto.SHA256,
	"1.2.840.10045.4.3.3": crypto.SHA384,
	"1.2.840.10045.4.3.4": crypto.SHA512,
	"1.2.840.10045.2.1":   0,
}

type cmsSigned struct {
	payload []byte
	certs   []*certificate
	signer  tlv
}

func parseCMS(der []byte) (cmsSigned, error) {
	top, err := parseOne(der)
	if err != nil {
		return cmsSigned{}, err
	}
	info, err := children(top)
	if err != nil {
		return cmsSigned{}, err
	}
	if len(info) != 2 {
		return cmsSigned{}, refuseReceipt("Receipt is not CMS signed data")
	}
	if oid, err := oidOf(info[0]); err != nil || oid != oidSignedData {
		return cmsSigned{}, refuseReceipt("Receipt is not CMS signed data")
	}
	wrapped, err := children(info[1])
	if err != nil || len(wrapped) == 0 {
		return cmsSigned{}, refuseReceipt("Receipt is not CMS signed data")
	}
	sd, err := children(wrapped[0])
	if err != nil || len(sd) < 3 {
		return cmsSigned{}, refuseReceipt("Receipt is not CMS signed data")
	}
	encap, err := children(sd[2])
	if err != nil || len(encap) == 0 {
		return cmsSigned{}, refuseReceipt("Receipt content is not data")
	}
	if oid, err := oidOf(encap[0]); err != nil || oid != oidCMSData {
		return cmsSigned{}, refuseReceipt("Receipt content is not data")
	}
	if len(encap) < 2 {
		return cmsSigned{}, refuseReceipt("Receipt has no embedded payload")
	}
	inner, err := children(encap[1])
	if err != nil || len(inner) == 0 || !isUniversal(inner[0], tagOctetString) {
		return cmsSigned{}, refuseReceipt("Receipt payload is not an OCTET STRING")
	}
	out := cmsSigned{payload: inner[0].content}
	var signerInfos *tlv
	for i := 3; i < len(sd); i++ {
		t := sd[i]
		switch {
		case t.cls == 2 && t.tag == 0:
			cs, err := children(t)
			if err != nil {
				return cmsSigned{}, err
			}
			for _, c := range cs {
				cert, err := parseCertificate(c.raw)
				if err != nil {
					return cmsSigned{}, err
				}
				out.certs = append(out.certs, cert)
			}
		case isUniversal(t, tagSet):
			t := t
			signerInfos = &t
		}
	}
	var signers []tlv
	if signerInfos != nil {
		if signers, err = children(*signerInfos); err != nil {
			return cmsSigned{}, err
		}
	}
	if len(signers) != 1 {
		return cmsSigned{}, refuseReceipt("Receipt needs exactly one signer")
	}
	out.signer = signers[0]
	return out, nil
}

func verifyCMSSigner(sd cmsSigned) (*certificate, error) {
	parts, err := children(sd.signer)
	if err != nil || len(parts) < 5 {
		return nil, refuseReceipt("Receipt has no signature")
	}
	sid := parts[1]
	digestAlgKids, err := children(parts[2])
	if err != nil || len(digestAlgKids) == 0 {
		return nil, refuseReceipt("Receipt digest algorithm is not supported")
	}
	digestOID, err := oidOf(digestAlgKids[0])
	if err != nil {
		return nil, err
	}
	digestHash, ok := cmsDigests[digestOID]
	if !ok {
		return nil, refuseReceipt("Receipt digest algorithm is not supported")
	}
	i := 3
	var signedAttrs *tlv
	if parts[i].cls == 2 && parts[i].tag == 0 {
		t := parts[i]
		signedAttrs = &t
		i++
	}
	if i >= len(parts) {
		return nil, refuseReceipt("Receipt has no signature")
	}
	sigAlgKids, err := children(parts[i])
	i++
	if err != nil || len(sigAlgKids) == 0 {
		return nil, refuseReceipt("Receipt signature algorithm is not supported")
	}
	sigOID, err := oidOf(sigAlgKids[0])
	if err != nil {
		return nil, err
	}
	if i >= len(parts) || !isUniversal(parts[i], tagOctetString) {
		return nil, refuseReceipt("Receipt has no signature")
	}
	signature := parts[i].content
	sigHash, known := cmsECSignatures[sigOID]
	if !known {
		return nil, refuseReceipt("Receipt signature algorithm is not supported")
	}
	if sigHash == 0 {
		sigHash = digestHash
	}
	if sigHash != digestHash {
		return nil, refuseReceipt("Receipt digest and signature hash differ")
	}

	if !isUniversal(sid, tagSequence) {
		return nil, refuseReceipt("Receipt signer id is not issuerAndSerialNumber")
	}
	sidKids, err := children(sid)
	if err != nil || len(sidKids) < 2 {
		return nil, refuseReceipt("Receipt signer id is malformed")
	}
	issuer, serial := sidKids[0], sidKids[1]
	serialHex := hexOfInteger(serial)
	var leaf *certificate
	for _, c := range sd.certs {
		if bytes.Equal(c.issuer, issuer.raw) && c.serialHex == serialHex {
			leaf = c
			break
		}
	}
	if leaf == nil {
		return nil, refuseReceipt("Receipt signer certificate is missing")
	}

	var signed []byte
	if signedAttrs != nil {
		var contentType string
		var digest []byte
		attrs, err := children(*signedAttrs)
		if err != nil {
			return nil, err
		}
		for _, attr := range attrs {
			kids, err := children(attr)
			if err != nil || len(kids) < 2 {
				continue
			}
			vals, err := children(kids[1])
			if err != nil || len(vals) == 0 {
				continue
			}
			typ, err := oidOf(kids[0])
			if err != nil {
				return nil, err
			}
			switch typ {
			case oidContentType:
				if contentType, err = oidOf(vals[0]); err != nil {
					return nil, err
				}
			case oidMessageDigest:
				digest = vals[0].content
			}
		}
		if contentType != oidCMSData {
			return nil, refuseReceipt("Receipt content type attribute is wrong")
		}
		if digest == nil || !constantTimeEqual(hashBytes(digestHash, sd.payload), digest) {
			return nil, refuseReceipt("Receipt digest does not match its payload")
		}
		// The signature covers the attributes as a SET OF (tag 0x31), not as the [0] they travel as.
		signed = append([]byte{}, signedAttrs.raw...)
		signed[0] = 0x31
	} else {
		signed = sd.payload
	}

	info, err := spkiInfo(leaf.spki)
	if err != nil {
		return nil, err
	}
	size, curveKnown := curveSizes[info.curve]
	pub, perr := x509.ParsePKIXPublicKey(leaf.spki)
	key, isEC := pub.(*ecdsa.PublicKey)
	if !curveKnown || info.alg != oidECPublicKey || perr != nil || !isEC {
		return nil, refuseReceipt("Receipt signer key is not an EC key")
	}
	r, s, err := ecdsaDERToInts(signature, size)
	if err != nil || !ecdsa.Verify(key, hashBytes(digestHash, signed), r, s) {
		return nil, refuseReceipt("Receipt signature is not valid")
	}
	return leaf, nil
}

// receiptChain orders the embedded certificates leaf first by following issuer to subject links,
// stopping before a self signed root: only configured anchors are trusted.
func receiptChain(leaf *certificate, certs []*certificate) []*certificate {
	chain := []*certificate{leaf}
	current := leaf
	for n := 0; n < len(certs); n++ {
		if bytes.Equal(current.issuer, current.subject) {
			break
		}
		var next *certificate
		for _, c := range certs {
			if bytes.Equal(c.subject, current.issuer) && !containsCert(chain, c) {
				next = c
				break
			}
		}
		if next == nil || bytes.Equal(next.subject, next.issuer) {
			break
		}
		chain = append(chain, next)
		current = next
	}
	return chain
}

func containsCert(list []*certificate, c *certificate) bool {
	for _, x := range list {
		if x == c {
			return true
		}
	}
	return false
}
