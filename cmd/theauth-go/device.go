package main

// device.go is `theauth-go device attest`, the Go twin of `theauth device attest`: it checks hardware
// attestation evidence offline with the same verifiers the enrollment hook uses, so an operator can
// reproduce a refusal from a device log without a running server. No config file is needed.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/iot/attest"
)

const attestHelp = `
theauth-go device attest android --evidence <file> --nonce <nonce> --revocation google|off [options]
theauth-go device attest apple   --evidence <file> --nonce <nonce> --app-id <TeamID.BundleID> [options]
theauth-go device attest tpm     --evidence <file> --nonce <nonce> --root <file> | --allow-unverified-ak [options]
theauth-go device attest tpm-certify --evidence <file> --nonce <nonce> --activation-key <hex> --root <file> | --allow-unverified-ek [options]
theauth-go device attest apple-assertion --assertion <file> --client-data <file> --app-id <id> --public-key <base64> --previous-counter <n>
theauth-go device attest apple-receipt   --receipt <file> [--app-id <id>] [--public-key <base64>] [--root <file>]

Checks evidence offline with the same verifier the enrollment hook uses. No config file is needed.
Exit code 0 when the evidence is accepted, 1 when it is refused, 2 for a usage error.

android: the evidence file is a JSON array of base64 DER certificates, leaf first (KeyStore.getCertificateChain).
apple:   the evidence file is JSON { "attestation": "<base64>", "keyId": "<base64>" } (App Attest attestKey output).
tpm:     the evidence file is JSON { "akPublic", "quote", "signature", "pcrs", "akCertificates" }.
tpm-certify: JSON { "ekPublic", "akPublic", "keyPublic", "certifyInfo", "signature", "activation": { "id", "secret" } }.
         --activation-key is the hex of the server secret behind the credential activation (the key the AS
         derives, see docs/device-attestation.md), so only run this where that key may be handled.

Common options:
  --evidence <file>         Evidence file
  --nonce <nonce>           The nonce the device bound into its evidence
  --root <file>             Trust anchor, PEM or base64 DER (repeatable). With --root only these are trusted
  --challenge utf8|base64url|hex   Encoding of the nonce (default utf8, tpm quotes often use hex)
  --key-thumbprint <t>      RFC 7638 thumbprint the attested key must have (android, apple and tpm-certify, jwk credential binding)
  --now <RFC 3339 time>     Verify as of this time
  --json                    Machine readable output

android options:
  --revocation google|off   Check serials against Google's status list, or skip (required, on purpose)
  --min-level tee|strongbox Lowest accepted security level (default tee)
  --boot verified|verified_or_self_signed|any   Boot policy (default verified)

apple options:
  --app-id <id>             Accepted App ID, TeamID.BundleID (required, repeatable)
  --environment production|development|any   AAGUID to accept (default production)
  --client-data-hash sha256|raw   How the app derived clientDataHash from its client data (default sha256)
  --bind client-data|attested-key|none   How the enrolled key is tied in (default: client-data when --key-thumbprint is given, else none)

tpm options:
  --allow-unverified-ak     Accept an attestation key without a certificate chain (development only)
  --pcr <bank>:<index>=<hex>   Expected PCR value, for example sha256:7=ab12... (repeatable)

tpm-certify options:
  --allow-unverified-ek     Accept an endorsement key without a certificate chain (development only)
`

type attestArgs struct {
	format                    string
	evidence, nonce           string
	revocation                string
	roots, appIDs, pcrFlags   stringList
	minLevel, boot, challenge string
	keyThumbprint             string
	environment, cdHash, bind string
	allowUnverified           bool
	activationKey             string
	now                       string
	asJSON                    bool
	assertionFile, clientData string
	publicKey, receiptFile    string
	previousCounter           int64
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func cmdDevice(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "attest" {
		_, _ = fmt.Fprintln(stderr, "usage: theauth-go device attest <format> [flags]")
		_, _ = fmt.Fprint(stderr, attestHelp)
		return 2
	}
	return cmdDeviceAttest(args[1:], stdout, stderr)
}

func cmdDeviceAttest(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, _ = fmt.Fprint(stdout, attestHelp)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	a := attestArgs{format: args[0]}
	fs := flag.NewFlagSet("device attest "+a.format, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&a.evidence, "evidence", "", "evidence file")
	fs.StringVar(&a.nonce, "nonce", "", "nonce bound into the evidence")
	fs.StringVar(&a.revocation, "revocation", "", "google or off")
	fs.Var(&a.roots, "root", "trust anchor file (repeatable)")
	fs.Var(&a.appIDs, "app-id", "accepted App ID (repeatable)")
	fs.Var(&a.pcrFlags, "pcr", "expected PCR value bank:index=hex (repeatable)")
	fs.StringVar(&a.minLevel, "min-level", "tee", "tee or strongbox")
	fs.StringVar(&a.boot, "boot", "verified", "boot policy")
	fs.StringVar(&a.challenge, "challenge", "utf8", "nonce encoding")
	fs.StringVar(&a.keyThumbprint, "key-thumbprint", "", "RFC 7638 thumbprint of the enrolled key")
	fs.StringVar(&a.environment, "environment", "production", "App Attest environment")
	fs.StringVar(&a.cdHash, "client-data-hash", "sha256", "sha256 or raw")
	fs.StringVar(&a.bind, "bind", "", "client-data, attested-key or none")
	fs.BoolVar(&a.allowUnverified, "allow-unverified-ak", false, "accept an AK without a chain")
	fs.BoolVar(&a.allowUnverified, "allow-unverified-ek", false, "accept an EK without a chain")
	fs.StringVar(&a.activationKey, "activation-key", "", "hex of the activation secret key")
	fs.StringVar(&a.now, "now", "", "verify as of this RFC 3339 time")
	fs.BoolVar(&a.asJSON, "json", false, "machine readable output")
	fs.StringVar(&a.assertionFile, "assertion", "", "App Attest assertion file")
	fs.StringVar(&a.clientData, "client-data", "", "client data file of the assertion")
	fs.StringVar(&a.publicKey, "public-key", "", "attested public key, base64 X9.62 point")
	fs.StringVar(&a.receiptFile, "receipt", "", "App Attest receipt file")
	fs.Int64Var(&a.previousCounter, "previous-counter", 0, "highest assertion counter accepted so far")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Unknown argument: %s\n", fs.Arg(0))
		return 2
	}
	var now func() time.Time
	if a.now != "" {
		t, err := time.Parse(time.RFC3339, a.now)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "--now needs an RFC 3339 time")
			return 2
		}
		now = func() time.Time { return t }
	}
	var roots []string
	for _, f := range a.roots {
		b, err := os.ReadFile(f)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "read root: %v\n", err)
			return 2
		}
		roots = append(roots, string(b))
	}
	var res attest.Result
	var err error
	switch a.format {
	case "android", "apple", "tpm", "tpm-certify":
		res, err = runVerifier(a, roots, now, stderr)
	case "apple-assertion":
		res, err = runAssertion(a)
	case "apple-receipt":
		res, err = runReceipt(a, roots, now)
	default:
		_, _ = fmt.Fprintln(stderr, "Supported attestation formats: android, apple, tpm, tpm-certify, apple-assertion, apple-receipt")
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 2
	}
	return printAttest(stdout, res, a.asJSON)
}

var pcrFlagRE = regexp.MustCompile(`^(sha1|sha256|sha384|sha512):(\d{1,2})=([0-9a-fA-F]+)$`)

func runVerifier(a attestArgs, roots []string, now func() time.Time, stderr io.Writer) (attest.Result, error) {
	if a.evidence == "" {
		return attest.Result{}, fmt.Errorf("missing --evidence <file>")
	}
	if a.nonce == "" {
		return attest.Result{}, fmt.Errorf("missing --nonce")
	}
	enc := attest.ChallengeEncoding(a.challenge)
	if enc != attest.ChallengeUTF8 && enc != attest.ChallengeBase64URL && enc != attest.ChallengeHex {
		return attest.Result{}, fmt.Errorf("--challenge must be utf8, base64url or hex")
	}
	if a.format == "android" && a.revocation != "google" && a.revocation != "off" {
		return attest.Result{}, fmt.Errorf("missing --revocation google|off")
	}
	raw, err := os.ReadFile(a.evidence)
	if err != nil {
		return attest.Result{}, fmt.Errorf("read evidence: %v", err)
	}
	var verify attest.Verifier
	switch a.format {
	case "apple":
		if len(a.appIDs) == 0 {
			return attest.Result{}, fmt.Errorf("missing --app-id <TeamID.BundleID>")
		}
		bind := a.bind
		if bind == "" {
			bind = attest.BindNone
			if a.keyThumbprint != "" {
				bind = attest.BindClientData
			}
		}
		verify, err = attest.NewAppleAppAttestVerifier(attest.AppleAppAttestOptions{
			AppIDs: a.appIDs, Roots: roots, Environment: a.environment, Bind: bind, ClientDataHash: a.cdHash,
			ChallengeEncoding: enc, Now: now,
		})
	case "tpm":
		pcrs := map[string]map[int]string{}
		for _, p := range a.pcrFlags {
			m := pcrFlagRE.FindStringSubmatch(p)
			if m == nil {
				return attest.Result{}, fmt.Errorf("--pcr must look like sha256:7=<hex>")
			}
			idx, _ := strconv.Atoi(m[2])
			if pcrs[m[1]] == nil {
				pcrs[m[1]] = map[int]string{}
			}
			pcrs[m[1]][idx] = m[3]
		}
		if len(roots) == 0 && !a.allowUnverified {
			return attest.Result{}, fmt.Errorf("pass --root <file> or --allow-unverified-ak")
		}
		verify, err = attest.NewTPM2QuoteVerifier(attest.TPM2Options{
			Roots: roots, AllowUnverifiedAk: a.allowUnverified, ChallengeEncoding: enc, ExpectedPCRs: pcrs, Now: now,
		})
	case "tpm-certify":
		if len(roots) == 0 && !a.allowUnverified {
			return attest.Result{}, fmt.Errorf("pass --root <file> or --allow-unverified-ek")
		}
		bind := attest.BindNone
		if a.keyThumbprint != "" {
			bind = attest.BindAttestedKey
		}
		verify, err = attest.NewTPM2CertifyVerifier(attest.TPM2CertifyOptions{
			EKRoots: roots, AllowUnverifiedEK: a.allowUnverified, Bind: bind, ChallengeEncoding: enc, Now: now,
		})
	default:
		switch a.revocation {
		case "google", "off":
		default:
			return attest.Result{}, fmt.Errorf("missing --revocation google|off")
		}
		level := attest.LevelTrustedEnvironment
		switch a.minLevel {
		case "tee":
		case "strongbox":
			level = attest.LevelStrongBox
		default:
			return attest.Result{}, fmt.Errorf("--min-level must be tee or strongbox")
		}
		opts := attest.AndroidKeyOptions{
			Roots: roots, MinSecurityLevel: level, BootPolicy: a.boot, BindKey: attest.Bool(a.keyThumbprint != ""),
			ChallengeEncoding: enc, Now: now, RevocationDisabled: a.revocation == "off",
		}
		if a.revocation == "google" {
			opts.Revocation = attest.GoogleRevocationList(attest.GoogleRevocationListOptions{})
		}
		verify, err = attest.NewAndroidKeyVerifier(opts)
	}
	if err != nil {
		return attest.Result{}, err
	}
	in := attest.Input{Evidence: string(raw), Nonce: a.nonce, EnrollmentID: "cli"}
	if a.keyThumbprint != "" {
		in.CredentialKind, in.CredentialKeyThumbprint = "jwk", a.keyThumbprint
	}
	if a.format == "tpm-certify" {
		key, err := hex.DecodeString(a.activationKey)
		if err != nil || len(key) == 0 {
			return attest.Result{}, fmt.Errorf("--activation-key must be the hex of the activation secret key")
		}
		in.ActivationKey = key
	}
	res, err := verify(context.Background(), in)
	if err != nil {
		return attest.Result{Reason: err.Error()}, nil
	}
	return res, nil
}

func runAssertion(a attestArgs) (attest.Result, error) {
	if a.assertionFile == "" || a.clientData == "" || a.publicKey == "" || len(a.appIDs) != 1 {
		return attest.Result{}, fmt.Errorf("apple-assertion needs --assertion <file>, --client-data <file>, --public-key <base64>, one --app-id and --previous-counter")
	}
	assertion, err := os.ReadFile(a.assertionFile)
	if err != nil {
		return attest.Result{}, fmt.Errorf("read assertion: %v", err)
	}
	cd, err := os.ReadFile(a.clientData)
	if err != nil {
		return attest.Result{}, fmt.Errorf("read client data: %v", err)
	}
	r := attest.VerifyAppleAssertion(attest.AppleAssertionInput{
		Assertion: strings.TrimSpace(string(assertion)), ClientData: cd, AppID: a.appIDs[0], PublicKey: a.publicKey,
		PreviousCounter: a.previousCounter,
	})
	if !r.OK {
		return attest.Result{Reason: r.Reason}, nil
	}
	return attest.Result{OK: true, Claims: map[string]any{"counter": r.Counter, "flags": r.Flags}}, nil
}

func runReceipt(a attestArgs, roots []string, now func() time.Time) (attest.Result, error) {
	if a.receiptFile == "" {
		return attest.Result{}, fmt.Errorf("missing --receipt <file>")
	}
	raw, err := os.ReadFile(a.receiptFile)
	if err != nil {
		return attest.Result{}, fmt.Errorf("read receipt: %v", err)
	}
	opts := attest.AppleReceiptOptions{PublicKey: a.publicKey, Roots: roots, Now: now}
	if len(a.appIDs) > 0 {
		opts.AppID = a.appIDs[0]
	}
	r := attest.VerifyAppleReceipt(strings.TrimSpace(string(raw)), opts)
	if !r.OK {
		return attest.Result{Reason: r.Reason}, nil
	}
	c := map[string]any{
		"appId": r.Receipt.AppID, "type": r.Receipt.Type, "environment": r.Receipt.Environment,
		"creationTime": r.Receipt.CreationTime.UTC().Format(time.RFC3339Nano), "token": r.Receipt.Token,
	}
	if r.Receipt.ExpirationTime != nil {
		c["expirationTime"] = r.Receipt.ExpirationTime.UTC().Format(time.RFC3339Nano)
	}
	if r.Receipt.NotBefore != nil {
		c["notBefore"] = r.Receipt.NotBefore.UTC().Format(time.RFC3339Nano)
	}
	if r.Receipt.RiskMetric != nil {
		c["riskMetric"] = *r.Receipt.RiskMetric
	}
	if r.Receipt.AttestedKeyThumbprint != "" {
		c["attestedKeyThumbprint"] = r.Receipt.AttestedKeyThumbprint
	}
	return attest.Result{OK: true, Claims: c}, nil
}

// printAttest writes the verdict like `theauth device attest`: Accepted with the claims, or Refused
// with the reason. Accepted evidence also prints the policy facts, what an attestation constraint reads.
func printAttest(w io.Writer, res attest.Result, asJSON bool) int {
	code := 1
	if res.OK {
		code = 0
	}
	if asJSON {
		out := map[string]any{"ok": res.OK}
		if res.OK {
			out["claims"] = res.Claims
			if f, ok := attest.FactsFromClaims(res.Claims); ok {
				out["facts"] = f.Map()
			}
		} else {
			out["reason"] = res.Reason
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, _ = fmt.Fprintln(w, string(b))
		return code
	}
	if !res.OK {
		_, _ = fmt.Fprintf(w, "Refused: %s\n", res.Reason)
		return code
	}
	_, _ = fmt.Fprintln(w, "Accepted")
	keys := make([]string, 0, len(res.Claims))
	for k := range res.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b, _ := json.Marshal(res.Claims[k])
		_, _ = fmt.Fprintf(w, "  %s: %s\n", k, b)
	}
	if f, ok := attest.FactsFromClaims(res.Claims); ok {
		b, _ := json.Marshal(f.Map())
		_, _ = fmt.Fprintf(w, "Policy facts: %s\n", b)
	}
	return code
}
