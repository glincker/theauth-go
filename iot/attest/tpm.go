package attest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	pcrIndexRE = regexp.MustCompile(`^\d{1,2}$`)
	pcrHexRE   = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// TPM2Options are the options of NewTPM2QuoteVerifier. Names follow the TypeScript
// Tpm2QuoteOptions.
type TPM2Options struct {
	// Roots are trust anchors (PEM or base64 DER) for the certificate that vouches for the
	// attestation key, usually issued by the TPM or platform vendor. The evidence must then
	// carry akCertificates, leaf first, and the leaf's public key must be the key that signed
	// the quote.
	Roots []string
	// AllowUnverifiedAk accepts an attestation key nobody vouches for. The quote then proves only
	// that whoever holds that key signed a TPM shaped structure, not that a real TPM exists.
	// Meant for development. Required when Roots is empty, so the choice is explicit.
	AllowUnverifiedAk bool
	// ChallengeEncoding is how the nonce string maps to the quote's qualifying data (extraData).
	// Default ChallengeUTF8.
	ChallengeEncoding ChallengeEncoding
	// ExpectedPCRs are known good PCR values by bank ("sha1", "sha256", "sha384", "sha512") and
	// index, as hex. Each listed PCR must be covered by the quote and equal.
	ExpectedPCRs map[string]map[int]string
	// RequireSafeClock requires the clock safe flag. Default true: the TPM says its clock has
	// not been reset since it was last read.
	RequireSafeClock *bool
	// Now is the clock for certificate validity. Tests inject one.
	Now func() time.Time
}

type tpmEvidence struct {
	akPublic       string
	quote          string
	signature      string
	pcrs           map[string]map[string]string
	akCertificates []string
}

// parseTPMEvidence validates the evidence JSON the way the TypeScript schema does.
func parseTPMEvidence(evidence string) (*tpmEvidence, error) {
	var parsed any
	if json.Unmarshal([]byte(evidence), &parsed) != nil {
		return nil, reasonErr("Evidence is not JSON")
	}
	bad := reasonErr("Evidence does not match the TPM quote format")
	obj, ok := parsed.(map[string]any)
	if !ok {
		return nil, bad
	}
	str := func(key string, max int) (string, bool) {
		s, ok := obj[key].(string)
		n := utf16Len(s)
		return s, ok && n >= 1 && n <= max
	}
	ev := &tpmEvidence{pcrs: map[string]map[string]string{}}
	var ok1, ok2, ok3 bool
	ev.akPublic, ok1 = str("akPublic", 4096)
	ev.quote, ok2 = str("quote", 4096)
	ev.signature, ok3 = str("signature", 2048)
	if !ok1 || !ok2 || !ok3 {
		return nil, bad
	}
	if raw, present := obj["pcrs"]; present {
		banks, ok := raw.(map[string]any)
		if !ok {
			return nil, bad
		}
		for bank, bv := range banks {
			vals, ok := bv.(map[string]any)
			if !ok {
				return nil, bad
			}
			inner := map[string]string{}
			for idx, hv := range vals {
				h, ok := hv.(string)
				if !ok || !pcrIndexRE.MatchString(idx) || !pcrHexRE.MatchString(h) {
					return nil, bad
				}
				inner[idx] = h
			}
			ev.pcrs[bank] = inner
		}
	}
	if raw, present := obj["akCertificates"]; present {
		list, ok := raw.([]any)
		if !ok || len(list) > 6 {
			return nil, bad
		}
		for _, c := range list {
			s, ok := c.(string)
			if !ok || utf16Len(s) < 1 || utf16Len(s) > 8192 {
				return nil, bad
			}
			ev.akCertificates = append(ev.akCertificates, s)
		}
	}
	return ev, nil
}

var cryptoHashByName = map[string]crypto.Hash{
	"sha1": crypto.SHA1, "sha256": crypto.SHA256, "sha384": crypto.SHA384, "sha512": crypto.SHA512,
}

func digestNamed(hash string, data []byte) []byte {
	h := cryptoHashByName[hash].New()
	h.Write(data)
	return h.Sum(nil)
}

func intBytes(n uint32) []byte {
	var out []byte
	for v := n; v > 0; v >>= 8 {
		out = append([]byte{byte(v)}, out...)
	}
	return out
}

func curveSize(curve string) int {
	switch curve {
	case "P-256":
		return 32
	case "P-384":
		return 48
	}
	return 66
}

// tpmKey is the verification key for the attestation key in the evidence.
type tpmKey struct {
	rsa *rsa.PublicKey
	ec  *ecdsa.PublicKey
}

func (p *tpmPublic) verificationKey(sig *tpmSignature) (*tpmKey, error) {
	if p.isRSA {
		return &tpmKey{rsa: &rsa.PublicKey{N: bigOf(p.rsaN), E: int(p.rsaE)}}, nil
	}
	if sig.alg == tpmAlgECDSA {
		size := curveSize(p.curve)
		if len(p.eccX) != size || len(p.eccY) != size {
			return nil, errors.New("bad point")
		}
		point := concat([]byte{4}, p.eccX, p.eccY)
		curve := elliptic.P521()
		switch p.curve {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		}
		key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, err
		}
		return &tpmKey{ec: key}, nil
	}
	return nil, reasonErr("Key and signature algorithm do not match")
}

func verifyQuoteSignature(key *tpmKey, pub *tpmPublic, sig *tpmSignature, hash string, message []byte) bool {
	digest := digestNamed(hash, message)
	if sig.alg == tpmAlgRSASSA && key.rsa != nil {
		return rsa.VerifyPKCS1v15(key.rsa, cryptoHashByName[hash], digest, sig.rsa) == nil
	}
	if sig.alg == tpmAlgECDSA && key.ec != nil && !pub.isRSA {
		size := curveSize(pub.curve)
		r, ok1 := trimInt(sig.r, size)
		s, ok2 := trimInt(sig.s, size)
		return ok1 && ok2 && ecdsa.Verify(key.ec, digest, r, s)
	}
	return false
}

// trimInt reads an ECDSA integer like the TypeScript leftPad: redundant leading zeros are
// dropped and a value wider than the curve is refused.
func trimInt(b []byte, size int) (*big.Int, bool) {
	for len(b) > size && b[0] == 0 {
		b = b[1:]
	}
	if len(b) > size {
		return nil, false
	}
	return bigOf(b), true
}

// akName is the AK name (Part 1, 16): nameAlg then H(TPMT_PUBLIC), the identifier a TPM uses for a key.
func akName(pub *tpmPublic) (string, bool) {
	alg, ok := hashByAlg[pub.nameAlg]
	if !ok {
		return "", false
	}
	return hex.EncodeToString(concat([]byte{byte(pub.nameAlg >> 8), byte(pub.nameAlg)}, digestNamed(alg, pub.raw))), true
}

func certMatchesAk(cert *certificate, pub *tpmPublic) bool {
	parsed, err := x509.ParsePKIXPublicKey(cert.spki)
	if err != nil {
		return false
	}
	info, err := spkiInfo(cert.spki)
	if err != nil {
		return false
	}
	if pub.isRSA {
		k, ok := parsed.(*rsa.PublicKey)
		return ok && info.alg == oidRSAEncryption && string(k.N.Bytes()) == string(pub.rsaN) &&
			string(intBytes(uint32(k.E))) == string(intBytes(pub.rsaE))
	}
	k, ok := parsed.(*ecdsa.PublicKey)
	if !ok || info.alg != oidECPublicKey || curveSizes[info.curve] != curveSize(pub.curve) || k.Curve.Params().Name != pub.curve {
		return false
	}
	size := curveSize(pub.curve)
	return string(k.X.FillBytes(make([]byte, size))) == string(pub.eccX) &&
		string(k.Y.FillBytes(make([]byte, size))) == string(pub.eccY)
}

func sortedBanks(m map[string]map[int]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// NewTPM2QuoteVerifier returns a verifier for TPM 2.0 quotes.
//
// Steps, from the TCG TPM 2.0 Library specification (Part 1 section 18 and Part 3 TPM2_Quote):
// the attestation key must be a restricted signing key that never leaves its TPM (fixedTPM,
// fixedParent), otherwise it could sign any bytes and the TPM_GENERATED magic would prove
// nothing. The quote must carry the magic and type quote, its qualifying data must equal the
// enrollment nonce, its signature must verify under the key with SHA-256 or stronger, and the
// PCR values in the evidence must hash to the signed digest. If Roots is set, a certificate
// chain must lead from the key to a root you trust.
//
// Not covered: the TPM2_MakeCredential and TPM2_ActivateCredential handshake that proves an AK
// sits in the same TPM as an endorsement key, TPM2_Certify of the enrolled device key (so the
// quote does not prove the enrolled credential lives in the TPM), and the event log.
func NewTPM2QuoteVerifier(opts TPM2Options) (Verifier, error) {
	if len(opts.Roots) == 0 && !opts.AllowUnverifiedAk {
		return nil, errors.New("attest: pass Roots to trust the attestation key, or AllowUnverifiedAk")
	}
	if !opts.ChallengeEncoding.valid() {
		return nil, fmt.Errorf("attest: unknown ChallengeEncoding %q", opts.ChallengeEncoding)
	}
	for _, bank := range sortedBanks(opts.ExpectedPCRs) {
		if _, ok := hashSize[bank]; !ok {
			return nil, fmt.Errorf("attest: unknown PCR bank %q", bank)
		}
	}
	anchors, err := parseAnchors(opts.Roots)
	if err != nil {
		return nil, fmt.Errorf("attest: trust anchor: %w", err)
	}
	requireSafe := boolOr(opts.RequireSafeClock, true)

	return func(_ context.Context, in Input) (Result, error) {
		if in.Nonce == "" {
			return fail("TPM quote needs the enrollment nonce")
		}
		ev, err := parseTPMEvidence(in.Evidence)
		if err != nil {
			return fail(err.Error())
		}
		var pub *tpmPublic
		var quote *tpmQuote
		var sig *tpmSignature
		var quoteBytes []byte
		decode := func() error {
			b, err := decodeBase64(ev.akPublic)
			if err != nil {
				return err
			}
			if pub, err = parseTPMPublic(b); err != nil {
				return err
			}
			if quoteBytes, err = decodeBase64(ev.quote); err != nil {
				return err
			}
			if quote, err = parseTPMQuote(quoteBytes); err != nil {
				return err
			}
			sb, err := decodeBase64(ev.signature)
			if err != nil {
				return err
			}
			sig, err = parseTPMSignature(sb)
			return err
		}
		if err := decode(); err != nil {
			return fail(err.Error())
		}

		// The key must be a TPM resident, restricted signing key.
		const need = attrRestricted | attrSign | attrFixedTPM | attrFixedParent
		if pub.attributes&need != need || pub.attributes&attrDecrypt != 0 {
			return fail("Attestation key is not a restricted, TPM resident signing key")
		}
		if pub.isRSA && (pub.rsaBit < 2048 || bigOf(pub.rsaN).BitLen() < 2048) {
			return fail("RSA attestation key is too small")
		}
		hash, ok := hashByAlg[sig.hash]
		if !ok || hash == "sha1" {
			return fail("Signature hash must be SHA-256 or stronger")
		}
		if pub.scheme != nil && (pub.scheme.alg != sig.alg || pub.scheme.hash != sig.hash) {
			return fail("Signature does not use the key's scheme")
		}
		if (sig.alg == tpmAlgRSASSA && !pub.isRSA) || (sig.alg != tpmAlgRSASSA && pub.isRSA) {
			return fail("Signature algorithm does not fit the key type")
		}
		key, err := pub.verificationKey(sig)
		if err != nil {
			return fail("Attestation key cannot be used for verification")
		}
		if !verifyQuoteSignature(key, pub, sig, hash, quoteBytes) {
			return fail("Quote signature is invalid")
		}

		expected, err := opts.ChallengeEncoding.encode(in.Nonce)
		if err != nil {
			return fail("Nonce cannot be encoded as the quote qualifying data")
		}
		if len(expected) == 0 || !constantTimeEqual(quote.extraData, expected) {
			return fail("Quote qualifying data does not match the enrollment nonce")
		}
		if requireSafe && !quote.safe {
			return fail("TPM clock is not marked safe")
		}

		// PCR values in the evidence must hash to the signed digest, in selection order.
		var parts [][]byte
		reported := map[string]any{}
		for _, sel := range quote.selections {
			bank, ok := hashByAlg[sel.hash]
			if !ok {
				return fail("Quote selects a PCR bank with an unknown hash")
			}
			values, ok := ev.pcrs[bank]
			if !ok {
				return fail(fmt.Sprintf("Evidence is missing the %s PCR values", bank))
			}
			for _, i := range sel.indexes {
				hx, ok := values[strconv.Itoa(i)]
				if !ok {
					return fail(fmt.Sprintf("Evidence is missing PCR %d of %s", i, bank))
				}
				v, err := hex.DecodeString(hx)
				if err != nil {
					return fail(fmt.Sprintf("PCR %d of %s is not valid hex", i, bank))
				}
				if len(v) != hashSize[bank] {
					return fail(fmt.Sprintf("PCR %d of %s has the wrong length", i, bank))
				}
				parts = append(parts, v)
				bv, _ := reported[bank].(map[string]any)
				if bv == nil {
					bv = map[string]any{}
				}
				bv[strconv.Itoa(i)] = strings.ToLower(hx)
				reported[bank] = bv
			}
		}
		if !constantTimeEqual(digestNamed(hash, concat(parts...)), quote.pcrDigest) {
			return fail("PCR values do not match the quoted digest")
		}
		for bank, wanted := range opts.ExpectedPCRs {
			for idx, hx := range wanted {
				var have any
				if bv, ok := reported[bank].(map[string]any); ok {
					have = bv[strconv.Itoa(idx)]
				}
				if have == nil || have != strings.ToLower(hx) {
					return fail(fmt.Sprintf("PCR %d of %s is not the expected value", idx, bank))
				}
			}
		}

		var root *certificate
		if len(anchors) > 0 {
			if len(ev.akCertificates) == 0 {
				return fail("Evidence has no attestation key certificate")
			}
			chain, err := parseAnchors(ev.akCertificates)
			if err != nil {
				return fail("Attestation key certificate is malformed")
			}
			res, err := verifyChain(chain, anchors, chainOptions{now: clock(opts.Now)})
			if err != nil {
				return fail(err.Error())
			}
			if !res.ok {
				return fail(res.reason)
			}
			root = res.anchor
			if !certMatchesAk(chain[0], pub) {
				return fail("Certificate does not belong to the key that signed the quote")
			}
		}

		claims := map[string]any{
			"format":        "tpm2-quote",
			"signatureHash": hash,
			"akVerified":    root != nil,
			"pcrs":          reported,
			"clockSafe":     quote.safe,
			"resetCount":    quote.resetCount,
			"restartCount":  quote.restartCount,
			// Same text as the TypeScript bigint toString(16): lowercase hex, no padding.
			"firmwareVersion": strconv.FormatUint(quote.firmwareVersion, 16),
		}
		if name, ok := akName(pub); ok {
			claims["akName"] = name
		}
		if pub.isRSA {
			claims["akKeyType"] = "rsa" + strconv.Itoa(int(pub.rsaBit))
		} else {
			claims["akKeyType"] = pub.curve
		}
		if root != nil {
			claims["attestationRootSerial"] = root.serialHex
		}
		return Result{OK: true, Claims: claims}, nil
	}, nil
}
