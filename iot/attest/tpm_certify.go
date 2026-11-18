package attest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// TPM 2.0 TPM2_Certify with a credential activation handshake, the Go twin of the TypeScript
// createTpm2CertifyVerifier. It proves three things a quote does not:
//   - the attestation key (AK) and the endorsement key (EK) live in one TPM: the device recovered, with
//     TPM2_ActivateCredential, a secret the server wrapped to that EK and that AK name (MakeCredential),
//   - the EK is genuine, when EKRoots is set: its certificate chains to a root you trust,
//   - the enrolled device key lives in that TPM and cannot be exported: the AK signed a TPM2_Certify of it
//     with the enrollment nonce as qualifying data, the certified name matches the key's public area, and
//     the key has fixedTPM, fixedParent and sensitiveDataOrigin.
//
// Specification: TCG TPM 2.0 Library Part 1 sections 16 (names), 18 and 24, Part 3 TPM2_Certify
// (section 18.2) and TPM2_ActivateCredential (section 12.5).

// TPM2CertifyOptions are the options of NewTPM2CertifyVerifier. Names follow the TypeScript
// Tpm2CertifyOptions.
type TPM2CertifyOptions struct {
	// EKRoots are trust anchors (PEM or base64 DER) for the endorsement key certificate, usually the TPM
	// manufacturer's roots. The evidence then carries ekCertificates, leaf first, and the leaf's public
	// key must be the EK that took part in the activation. This is what says the TPM is genuine.
	EKRoots []string
	// AllowUnverifiedEK accepts an EK nobody vouches for. Required when EKRoots is empty, so the choice
	// is explicit.
	AllowUnverifiedEK bool
	// Bind says how the certified key relates to the credential the device enrolls. BindAttestedKey
	// (default): the TPM key must be the enrolled jwk credential (same RFC 7638 thumbprint). BindNone:
	// the certification stands alone.
	Bind string
	// ChallengeEncoding is how the nonce string maps to the certify qualifying data. Default ChallengeUTF8.
	ChallengeEncoding ChallengeEncoding
	// RequireSafeClock requires the clock safe flag. Default true.
	RequireSafeClock *bool
	// Now is the clock for certificate validity. Tests inject one.
	Now func() time.Time
}

type certifyEvidence struct {
	ekPublic, akPublic, keyPublic, certifyInfo, signature string
	activationID, activationSecret                        string
	ekCertificates                                        []string
}

func parseCertifyEvidence(evidence string) (*certifyEvidence, error) {
	var parsed any
	if json.Unmarshal([]byte(evidence), &parsed) != nil {
		return nil, reasonErr("Evidence is not JSON")
	}
	bad := reasonErr("Evidence does not match the TPM certify format")
	obj, ok := parsed.(map[string]any)
	if !ok {
		return nil, bad
	}
	str := func(m map[string]any, key string, max int) (string, bool) {
		s, ok := m[key].(string)
		n := utf16Len(s)
		return s, ok && n >= 1 && n <= max
	}
	ev := &certifyEvidence{}
	oks := [6]bool{}
	ev.ekPublic, oks[0] = str(obj, "ekPublic", 4096)
	ev.akPublic, oks[1] = str(obj, "akPublic", 4096)
	ev.keyPublic, oks[2] = str(obj, "keyPublic", 4096)
	ev.certifyInfo, oks[3] = str(obj, "certifyInfo", 4096)
	ev.signature, oks[4] = str(obj, "signature", 2048)
	act, isObj := obj["activation"].(map[string]any)
	if isObj {
		var a, b bool
		ev.activationID, a = str(act, "id", 128)
		ev.activationSecret, b = str(act, "secret", 512)
		oks[5] = a && b
	}
	for _, v := range oks {
		if !v {
			return nil, bad
		}
	}
	if raw, present := obj["ekCertificates"]; present {
		list, ok := raw.([]any)
		if !ok || len(list) > 6 {
			return nil, bad
		}
		for _, c := range list {
			s, ok := c.(string)
			if !ok || utf16Len(s) < 1 || utf16Len(s) > 8192 {
				return nil, bad
			}
			ev.ekCertificates = append(ev.ekCertificates, s)
		}
	}
	return ev, nil
}

func tpmKeyType(p *tpmPublic) string {
	if p.isRSA {
		return "rsa" + strconv.Itoa(int(p.rsaBit))
	}
	return p.curve
}

// tpmJWKThumbprint is the RFC 7638 SHA-256 thumbprint of an ECC TPM key, "" for any other key.
func tpmJWKThumbprint(p *tpmPublic) string {
	if p.isRSA {
		return ""
	}
	b64 := base64.RawURLEncoding.EncodeToString
	canonical := fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, p.curve, b64(p.eccX), b64(p.eccY))
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:])
}

// NewTPM2CertifyVerifier returns a verifier for TPM2_Certify with credential activation. The server
// side of the activation is MakeCredential with DeriveActivationSecret, keyed by the same key that
// enrollment passes in Input.ActivationKey.
func NewTPM2CertifyVerifier(opts TPM2CertifyOptions) (Verifier, error) {
	if len(opts.EKRoots) == 0 && !opts.AllowUnverifiedEK {
		return nil, errors.New("attest: pass EKRoots to trust the endorsement key, or AllowUnverifiedEK")
	}
	if !opts.ChallengeEncoding.valid() {
		return nil, fmt.Errorf("attest: unknown ChallengeEncoding %q", opts.ChallengeEncoding)
	}
	bind := opts.Bind
	if bind == "" {
		bind = BindAttestedKey
	}
	if bind != BindAttestedKey && bind != BindNone {
		return nil, fmt.Errorf("attest: unknown Bind %q", opts.Bind)
	}
	anchors, err := parseAnchors(opts.EKRoots)
	if err != nil {
		return nil, fmt.Errorf("attest: trust anchor: %w", err)
	}
	requireSafe := boolOr(opts.RequireSafeClock, true)

	return func(_ context.Context, in Input) (Result, error) {
		if in.Nonce == "" {
			return fail("TPM certify needs the enrollment nonce")
		}
		if len(in.ActivationKey) == 0 {
			return fail("TPM certify needs the activation service")
		}
		ev, err := parseCertifyEvidence(in.Evidence)
		if err != nil {
			return fail(err.Error())
		}
		var ak, ek, key *tpmPublic
		var cert *tpmCertify
		var info []byte
		var sig *tpmSignature
		decode := func() error {
			b, err := decodeBase64(ev.akPublic)
			if err != nil {
				return err
			}
			if ak, err = parseTPMPublic(b); err != nil {
				return err
			}
			if b, err = decodeBase64(ev.ekPublic); err != nil {
				return err
			}
			if ek, err = parseTPMPublicOpts(b, true); err != nil {
				return err
			}
			if b, err = decodeBase64(ev.keyPublic); err != nil {
				return err
			}
			if key, err = parseTPMPublic(b); err != nil {
				return err
			}
			if info, err = decodeBase64(ev.certifyInfo); err != nil {
				return err
			}
			if cert, err = parseTPMCertify(info); err != nil {
				return err
			}
			if b, err = decodeBase64(ev.signature); err != nil {
				return err
			}
			sig, err = parseTPMSignature(b)
			return err
		}
		if err := decode(); err != nil {
			return fail(err.Error())
		}

		const need = attrRestricted | attrSign | attrFixedTPM | attrFixedParent
		if ak.attributes&need != need || ak.attributes&attrDecrypt != 0 {
			return fail("Attestation key is not a restricted, TPM resident signing key")
		}
		if ak.isRSA && (ak.rsaBit < 2048 || bigOf(ak.rsaN).BitLen() < 2048) {
			return fail("RSA attestation key is too small")
		}
		hash, ok := hashByAlg[sig.hash]
		if !ok || hash == "sha1" {
			return fail("Signature hash must be SHA-256 or stronger")
		}
		if ak.scheme != nil && (ak.scheme.alg != sig.alg || ak.scheme.hash != sig.hash) {
			return fail("Signature does not use the key's scheme")
		}
		if (sig.alg == tpmAlgRSASSA && !ak.isRSA) || (sig.alg != tpmAlgRSASSA && ak.isRSA) {
			return fail("Signature algorithm does not fit the key type")
		}
		akKey, err := ak.verificationKey(sig)
		if err != nil {
			return fail("Attestation key cannot be used for verification")
		}
		if !verifyQuoteSignature(akKey, ak, sig, hash, info) {
			return fail("Certify signature is invalid")
		}

		expected, err := opts.ChallengeEncoding.encode(in.Nonce)
		if err != nil {
			return fail("Nonce cannot be encoded as the certify qualifying data")
		}
		if len(expected) == 0 || !constantTimeEqual(cert.extraData, expected) {
			return fail("Certify qualifying data does not match the enrollment nonce")
		}
		if requireSafe && !cert.safe {
			return fail("TPM clock is not marked safe")
		}

		keyName, err := tpmObjectName(key)
		if err != nil {
			return fail("Certified key uses an unsupported name algorithm")
		}
		if !constantTimeEqual(keyName, cert.name) {
			return fail("Certified name does not match the key")
		}
		const keyNeed = attrFixedTPM | attrFixedParent | attrSensitive
		if key.attributes&keyNeed != keyNeed {
			return fail("Certified key can leave the TPM or was not generated in it")
		}
		thumb := tpmJWKThumbprint(key)
		if bind == BindAttestedKey {
			if in.CredentialKind != "jwk" || in.CredentialKeyThumbprint == "" {
				return fail("Enroll a jwk credential: the certified TPM key must be the enrolled key")
			}
			if thumb == "" || thumb != in.CredentialKeyThumbprint {
				return fail("Certified key is not the enrolled key")
			}
		}

		// Credential activation: the device recovered a secret only the TPM holding this EK and this AK could.
		secret, err := decodeActivationSecret(ev.activationSecret)
		if err != nil {
			return fail("Activation secret is not valid")
		}
		akName, err1 := tpmObjectName(ak)
		ekName, err2 := tpmObjectName(ek)
		if err1 != nil || err2 != nil {
			return fail("Key uses an unsupported name algorithm")
		}
		if !constantTimeEqual(DeriveActivationSecret(in.ActivationKey, in.Nonce, akName, ekName), secret) {
			return fail("Credential activation is unknown, expired, used or wrong")
		}

		var root *certificate
		if len(anchors) > 0 {
			if len(ev.ekCertificates) == 0 {
				return fail("Evidence has no endorsement key certificate")
			}
			chain, err := parseAnchors(ev.ekCertificates)
			if err != nil {
				return fail("Endorsement key certificate is malformed")
			}
			res, err := verifyChain(chain, anchors, chainOptions{now: clock(opts.Now)})
			if err != nil {
				return fail(err.Error())
			}
			if !res.ok {
				return fail(res.reason)
			}
			root = res.anchor
			if !certMatchesAk(chain[0], ek) {
				return fail("Certificate does not belong to the endorsement key")
			}
		}

		claims := map[string]any{
			"format":        "tpm2-certify",
			"akName":        hex.EncodeToString(akName),
			"ekName":        hex.EncodeToString(ekName),
			"akKeyType":     tpmKeyType(ak),
			"ekKeyType":     tpmKeyType(ek),
			"keyName":       hex.EncodeToString(keyName),
			"keyType":       tpmKeyType(key),
			"signatureHash": hash,
			"activated":     true,
			"ekVerified":    root != nil,
			"clockSafe":     cert.safe,
			"resetCount":    cert.resetCount,
			"restartCount":  cert.restartCount,
			// Same text as the TypeScript bigint toString(16): lowercase hex, no padding.
			"firmwareVersion": strconv.FormatUint(cert.firmwareVersion, 16),
		}
		if thumb != "" {
			claims["attestedKeyThumbprint"] = thumb
		}
		if root != nil {
			claims["attestationRootSerial"] = root.serialHex
		}
		return Result{OK: true, Claims: claims}, nil
	}, nil
}

// decodeActivationSecret reads the secret the device recovered: hex or base64 (url or standard), like
// the TypeScript bytesOf.
func decodeActivationSecret(s string) ([]byte, error) {
	if len(s)%2 == 0 && pcrHexRE.MatchString(s) {
		return hex.DecodeString(s)
	}
	return decodeBase64(s)
}
