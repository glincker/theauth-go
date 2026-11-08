package attest

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

// Apple App Attest receipts ("Assessing fraud risk"), the Go twin of the TypeScript
// verifyAppleReceipt: a CMS SignedData (RFC 5652) signed by Apple's "Application Attestation Fraud
// Receipt Signing" certificate under "Apple Application Integration CA 5 - G1" and Apple Root CA - G3.
// The payload is a SET of attributes SEQUENCE {INTEGER type, INTEGER version, OCTET STRING value}.
// Fixtures: the two receipts of veehaitch/devicecheck-appattest ios-14.4.yaml (Apache-2.0).
//
// Verifying a receipt proves Apple issued it for this app and key. The risk metric is the number of
// attested keys Apple saw for the device in the last 30 days. Refreshing it means sending the
// receipt to Apple's fraud metric endpoint with your own credentials, which this package does not do.

// AppleReceiptOptions tunes VerifyAppleReceipt.
type AppleReceiptOptions struct {
	// AppID, when set, requires the receipt to be for this <TeamID>.<BundleID>.
	AppID string
	// PublicKey, when set, requires the receipt to be for this attested key: an X9.62 point (65 bytes)
	// as base64. Use the attestedPublicKey claim.
	PublicKey string
	// Roots are PEM or base64 DER trust anchors. Default AppleReceiptRoots.
	Roots []string
	// Now is the clock for certificate validity and receipt expiry. Default time.Now.
	Now func() time.Time
}

// AppleReceipt is the verified content of a receipt.
type AppleReceipt struct {
	AppID string
	// Type is "ATTEST" for the receipt that comes with an attestation, "RECEIPT" for one from an
	// assertion or a refresh.
	Type         string
	Environment  string
	CreationTime time.Time
	// NotBefore is the earliest time a new fraud metric can be requested with this receipt.
	NotBefore      *time.Time
	ExpirationTime *time.Time
	// RiskMetric is only present in a refreshed receipt.
	RiskMetric *int
	// Token is what to send to Apple to refresh the receipt.
	Token      string
	ClientHash []byte
	// AttestedKeyThumbprint is the RFC 7638 thumbprint of the key inside the receipt.
	AttestedKeyThumbprint string
}

// AppleReceiptResult is the verdict. Reason is the same sentence as the TypeScript verifier.
type AppleReceiptResult struct {
	OK      bool
	Reason  string
	Receipt AppleReceipt
}

type receiptRefusal string

func (r receiptRefusal) Error() string { return string(r) }

func refuseReceipt(reason string) error { return receiptRefusal(reason) }

var isoStart = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`)

func receiptTime(b []byte) *time.Time {
	if !utf8.Valid(b) || !isoStart.Match(b) {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, string(b))
	if err != nil {
		return nil
	}
	return &t
}

func parseReceiptPayload(payload []byte) (map[int64][]byte, error) {
	set, err := parseOne(payload)
	if err != nil {
		return nil, err
	}
	if !isUniversal(set, tagSet) {
		return nil, refuseReceipt("Receipt payload is not a SET")
	}
	seqs, err := children(set)
	if err != nil {
		return nil, err
	}
	attrs := map[int64][]byte{}
	for _, seq := range seqs {
		kids, err := children(seq)
		if err != nil || len(kids) < 3 || !isUniversal(kids[2], tagOctetString) {
			return nil, refuseReceipt("Receipt attribute is malformed")
		}
		n, err := intOf(kids[0])
		if err != nil {
			return nil, err
		}
		if _, dup := attrs[n]; dup {
			return nil, refuseReceipt("Receipt repeats an attribute")
		}
		attrs[n] = kids[2].content
	}
	return attrs, nil
}

func spkiPoint(spki []byte) []byte {
	top, err := parseOne(spki)
	if err != nil {
		return nil
	}
	kids, err := children(top)
	if err != nil || len(kids) < 2 {
		return nil
	}
	c := kids[1].content
	if len(c) == 66 && c[0] == 0 && c[1] == 4 {
		return c[1:]
	}
	return nil
}

// VerifyAppleReceipt verifies an App Attest receipt: Apple's CMS signature and chain, the app id,
// optionally the key, and expiry. receipt is base64 (std or url) of the CMS blob. A refusal is a
// Result with OK false, never an error.
func VerifyAppleReceipt(receipt string, opts AppleReceiptOptions) AppleReceiptResult {
	res, err := verifyAppleReceipt(receipt, opts)
	if err == nil {
		return AppleReceiptResult{OK: true, Receipt: res}
	}
	var refusal receiptRefusal
	if errors.As(err, &refusal) {
		return AppleReceiptResult{Reason: string(refusal)}
	}
	var de *derError
	if errors.As(err, &de) {
		return AppleReceiptResult{Reason: "Receipt is not valid CMS"}
	}
	return AppleReceiptResult{Reason: "Receipt could not be verified"}
}

func verifyAppleReceipt(receipt string, opts AppleReceiptOptions) (AppleReceipt, error) {
	raw, err := decodeBase64(receipt)
	if err != nil {
		return AppleReceipt{}, err
	}
	der, err := berToDER(raw)
	if err != nil {
		return AppleReceipt{}, err
	}
	sd, err := parseCMS(der)
	if err != nil {
		return AppleReceipt{}, err
	}
	leaf, err := verifyCMSSigner(sd)
	if err != nil {
		return AppleReceipt{}, err
	}
	roots := opts.Roots
	if roots == nil {
		roots = AppleReceiptRoots
	}
	anchors, err := parseAnchors(roots)
	if err != nil {
		return AppleReceipt{}, err
	}
	now := time.Now()
	if opts.Now != nil {
		now = opts.Now()
	}
	chain, err := verifyChain(receiptChain(leaf, sd.certs), anchors, chainOptions{now: now})
	if err != nil {
		return AppleReceipt{}, err
	}
	if !chain.ok {
		return AppleReceipt{}, refuseReceipt(chain.reason)
	}
	attrs, err := parseReceiptPayload(sd.payload)
	if err != nil {
		return AppleReceipt{}, err
	}
	appIDBytes, tokenBytes, typeBytes, created := attrs[2], attrs[5], attrs[6], attrs[12]
	if appIDBytes == nil || tokenBytes == nil || typeBytes == nil || created == nil {
		return AppleReceipt{}, refuseReceipt("Receipt is missing fields")
	}
	for _, b := range [][]byte{appIDBytes, tokenBytes, typeBytes} {
		if !utf8.Valid(b) {
			return AppleReceipt{}, refuseReceipt("Receipt could not be verified")
		}
	}
	out := AppleReceipt{AppID: string(appIDBytes), Type: string(typeBytes), Token: string(tokenBytes), ClientHash: attrs[4]}
	if out.ClientHash == nil {
		out.ClientHash = []byte{}
	}
	ct := receiptTime(created)
	if ct == nil {
		return AppleReceipt{}, refuseReceipt("Receipt creation time is not valid")
	}
	out.CreationTime = *ct
	if expiry, has := attrs[21]; has {
		et := receiptTime(expiry)
		if et == nil {
			return AppleReceipt{}, refuseReceipt("Receipt expiration time is not valid")
		}
		out.ExpirationTime = et
		if !et.After(now) {
			return AppleReceipt{}, refuseReceipt("Receipt has expired")
		}
	}
	if opts.AppID != "" && out.AppID != opts.AppID {
		return AppleReceipt{}, refuseReceipt("Receipt is for another App ID")
	}
	if keyCert := attrs[3]; keyCert != nil {
		cert, err := parseCertificate(keyCert)
		if err != nil {
			return AppleReceipt{}, err
		}
		out.AttestedKeyThumbprint = keyThumbprint(cert.spki)
		if opts.PublicKey != "" {
			want, err := decodeBase64(opts.PublicKey)
			if err != nil {
				return AppleReceipt{}, err
			}
			if have := spkiPoint(cert.spki); have == nil || !bytes.Equal(have, want) {
				return AppleReceipt{}, refuseReceipt("Receipt is for another key")
			}
		}
	} else if opts.PublicKey != "" {
		return AppleReceipt{}, refuseReceipt("Receipt carries no key to compare")
	}
	if nb, has := attrs[19]; has {
		out.NotBefore = receiptTime(nb)
	}
	if m, has := attrs[17]; has {
		if !utf8.Valid(m) {
			return AppleReceipt{}, refuseReceipt("Receipt risk metric is not a number")
		}
		n, err := strconv.Atoi(string(m))
		if err != nil {
			return AppleReceipt{}, refuseReceipt("Receipt risk metric is not a number")
		}
		out.RiskMetric = &n
	}
	if env, has := attrs[7]; has && utf8.Valid(env) {
		out.Environment = string(env)
	}
	return out, nil
}
