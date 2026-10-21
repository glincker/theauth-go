package attest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// RevocationCheck reports whether a certificate serial (lowercase hex without leading zeros) is
// revoked. An error means the answer is unknown, which refuses the enrollment.
type RevocationCheck func(ctx context.Context, serialHex string) (bool, error)

// AndroidKeyOptions are the options of NewAndroidKeyVerifier. Names follow the TypeScript
// AndroidKeyAttestationOptions.
type AndroidKeyOptions struct {
	// Revocation decides certificate revocation. Google says every certificate must be checked
	// against its status list, so there is no default: pass GoogleRevocationList, your own
	// lookup, or set RevocationDisabled to opt out knowingly.
	Revocation RevocationCheck
	// RevocationDisabled skips the revocation check on purpose.
	RevocationDisabled bool
	// Roots are trust anchors as PEM or base64 DER. Default: the Google Hardware Attestation
	// roots bundled with this package (GoogleAttestationRoots).
	Roots []string
	// MinSecurityLevel is the lowest accepted security level of both the attestation and the
	// key: LevelTrustedEnvironment (default) or LevelStrongBox.
	MinSecurityLevel string
	// BootPolicy is "verified" (default: state Verified and a locked bootloader),
	// "verified_or_self_signed" (also SelfSigned when locked) or "any" (skips the check, for
	// development devices).
	BootPolicy string
	// RequireGeneratedKey requires origin GENERATED in the hardware list, so an imported key is
	// refused. Default true.
	RequireGeneratedKey *bool
	// BindKey requires the attested key to be the key the device enrolls (credential kind jwk,
	// same RFC 7638 thumbprint). Default true.
	BindKey *bool
	// ChallengeEncoding is how the device encoded the nonce into the attestation challenge.
	// Default ChallengeUTF8, the nonce string as bytes.
	ChallengeEncoding ChallengeEncoding
	// AllowedPackages, when non nil, requires the attested app to be one of these Android
	// package names. An empty non nil list refuses everything. Software enforced, so it limits
	// mistakes, not a compromised OS.
	AllowedPackages []string
	// Now is the clock for validity checks. Tests inject one.
	Now func() time.Time
}

var bootAccepted = map[string][]string{
	"verified":                {BootVerified},
	"verified_or_self_signed": {BootVerified, BootSelfSigned},
	"any":                     {BootVerified, BootSelfSigned, BootUnverified, BootFailed},
}

var levelRank = map[string]int{LevelSoftware: 0, LevelTrustedEnvironment: 1, LevelStrongBox: 2}

// googleFactoryRoot is the subject serialNumber of the Google root whose factory certificates
// stay valid after their notAfter date.
const googleFactoryRoot = "f92009e853b6b045"

// ParseAndroidKeyEvidence reads Android key attestation evidence: a JSON array of base64
// certificates, leaf first, or an object {"chain": [...]}. It returns the DER certificates.
func ParseAndroidKeyEvidence(evidence string) ([][]byte, error) {
	var parsed any
	if err := json.Unmarshal([]byte(evidence), &parsed); err != nil {
		return nil, reasonErr("Evidence is not JSON")
	}
	var list []any
	var isList bool
	switch v := parsed.(type) {
	case []any:
		list, isList = v, true
	case map[string]any:
		list, isList = v["chain"].([]any)
	}
	if !isList || len(list) == 0 || len(list) > 8 {
		return nil, reasonErr("Evidence needs a certificate list of 1 to 8 entries")
	}
	out := make([][]byte, 0, len(list))
	for _, c := range list {
		s, ok := c.(string)
		if !ok {
			return nil, reasonErr("Certificates must be base64 strings")
		}
		der, err := certBytesFromText(s)
		if err != nil {
			return nil, err
		}
		out = append(out, der)
	}
	return out, nil
}

// NewAndroidKeyVerifier returns a verifier for Android Key Attestation.
//
// It follows Google's verification steps: chain to a Google root, no revoked certificate, the
// key attestation extension in the leaf only, security level, a TEE enforced root of trust, and
// a challenge equal to the enrollment nonce. Sources:
// https://developer.android.com/privacy-and-security/security-key-attestation and
// https://source.android.com/docs/security/features/keystore/attestation
func NewAndroidKeyVerifier(opts AndroidKeyOptions) (Verifier, error) {
	if opts.Revocation == nil && !opts.RevocationDisabled {
		return nil, errors.New("attest: set Revocation (for example GoogleRevocationList) or RevocationDisabled")
	}
	if !opts.ChallengeEncoding.valid() {
		return nil, fmt.Errorf("attest: unknown ChallengeEncoding %q", opts.ChallengeEncoding)
	}
	minLevelName := opts.MinSecurityLevel
	if minLevelName == "" {
		minLevelName = LevelTrustedEnvironment
	}
	if minLevelName != LevelTrustedEnvironment && minLevelName != LevelStrongBox {
		return nil, fmt.Errorf("attest: unknown MinSecurityLevel %q", opts.MinSecurityLevel)
	}
	bootName := opts.BootPolicy
	if bootName == "" {
		bootName = "verified"
	}
	boot, ok := bootAccepted[bootName]
	if !ok {
		return nil, fmt.Errorf("attest: unknown BootPolicy %q", opts.BootPolicy)
	}
	roots := opts.Roots
	if roots == nil {
		roots = GoogleAttestationRoots
	}
	anchors, err := parseAnchors(roots)
	if err != nil {
		return nil, fmt.Errorf("attest: trust anchor: %w", err)
	}
	minLevel := levelRank[minLevelName]
	requireGenerated := boolOr(opts.RequireGeneratedKey, true)
	bindKey := boolOr(opts.BindKey, true)

	return func(ctx context.Context, in Input) (Result, error) {
		if in.Nonce == "" {
			return fail("Android key attestation needs the enrollment nonce")
		}
		ders, err := ParseAndroidKeyEvidence(in.Evidence)
		var chain []*certificate
		if err == nil {
			for _, der := range ders {
				c, perr := parseCertificate(der)
				if perr != nil {
					err = perr
					break
				}
				chain = append(chain, c)
			}
		}
		if err != nil {
			return fail(err.Error())
		}
		now := clock(opts.Now)
		leaf := chain[0]
		hasProvisioning := false
		for _, c := range chain {
			if _, has := c.extensions[oidProvisioningInfo]; has {
				hasProvisioning = true
			}
		}

		// First pass validates against the anchors. Factory certificates of the 2016 root outlive
		// their notAfter by Google's own rule, so the validity check is skipped for those chains only.
		result, err := verifyChain(chain, anchors, chainOptions{now: now})
		if err != nil {
			return fail(err.Error())
		}
		if !result.ok && !hasProvisioning {
			retry, rerr := verifyChain(chain, anchors, chainOptions{now: now, skipValidity: true})
			if rerr == nil && retry.ok && retry.anchor.hasSubjectSerial && retry.anchor.subjectSerialNumber == googleFactoryRoot {
				result = retry
			}
		}
		if !result.ok {
			return fail(result.reason)
		}

		if !opts.RevocationDisabled {
			for _, c := range chain {
				revoked, rerr := opts.Revocation(ctx, c.serialHex)
				if rerr != nil {
					return Result{}, fmt.Errorf("attest: revocation check: %w", rerr)
				}
				if revoked {
					return fail("An attestation certificate is revoked")
				}
			}
		}

		// Only the occurrence nearest the root is trusted. We need it in the leaf and nowhere else.
		var carriers []int
		for i, c := range chain {
			if _, has := c.extensions[oidKeyAttestation]; has {
				carriers = append(carriers, i)
			}
		}
		if len(carriers) != 1 || carriers[0] != 0 {
			return fail("The key attestation extension must appear once, in the leaf certificate")
		}
		// With provisioning info, the key attestation extension must sit in the next certificate down.
		provisionIdx := -1
		for i, c := range chain {
			if _, has := c.extensions[oidProvisioningInfo]; has {
				provisionIdx = i
			}
		}
		if provisionIdx >= 0 && provisionIdx != 1 {
			return fail("The provisioning information extension is not in the certificate above the leaf")
		}

		kd, err := parseKeyDescription(leaf.extensions[oidKeyAttestation].value)
		if err != nil {
			return fail("Key attestation extension is malformed")
		}
		expected, err := opts.ChallengeEncoding.encode(in.Nonce)
		if err != nil {
			return fail("Nonce cannot be encoded as the attestation challenge")
		}
		if !constantTimeEqual(kd.attestationChallenge, expected) {
			return fail("Attestation challenge does not match the enrollment nonce")
		}
		if levelRank[kd.attestationSecurityLevel] < minLevel || levelRank[kd.keymasterSecurityLevel] < minLevel {
			return fail("Key is not protected by the required security level")
		}
		hw := kd.hardwareEnforced
		if requireGenerated && (hw.origin == nil || *hw.origin != 0) {
			return fail("Key was not generated in hardware")
		}
		rot := hw.rootOfTrust
		if rot == nil {
			return fail("Hardware enforced root of trust is missing")
		}
		if bootName != "any" && (!contains(boot, rot.verifiedBootState) || !rot.deviceLocked) {
			return fail("Device boot state is not verified and locked")
		}
		app := kd.softwareEnforced.application
		if opts.AllowedPackages != nil {
			allowed := false
			if app != nil {
				for _, n := range app.packages {
					if contains(opts.AllowedPackages, n) {
						allowed = true
					}
				}
			}
			if !allowed {
				return fail("Attested app is not an allowed package")
			}
		}

		attestedKey := keyThumbprint(leaf.spki)
		if bindKey {
			if in.CredentialKind != "jwk" || in.CredentialKeyThumbprint == "" {
				return fail("Enroll a jwk credential: the attested key must be the enrolled key")
			}
			if attestedKey == "" || attestedKey != in.CredentialKeyThumbprint {
				return fail("Attested key is not the enrolled key")
			}
		}

		claims := map[string]any{
			"format":                "android-key-attestation",
			"attestationVersion":    kd.attestationVersion,
			"securityLevel":         kd.attestationSecurityLevel,
			"keySecurityLevel":      kd.keymasterSecurityLevel,
			"verifiedBootState":     rot.verifiedBootState,
			"deviceLocked":          rot.deviceLocked,
			"attestationRootSerial": nil,
		}
		if rot.verifiedBootKey != "" {
			claims["verifiedBootKey"] = rot.verifiedBootKey
		}
		if hw.osVersion != nil {
			claims["osVersion"] = *hw.osVersion
		}
		if hw.osPatchLevel != nil {
			claims["osPatchLevel"] = *hw.osPatchLevel
		}
		if attestedKey != "" {
			claims["attestedKeyThumbprint"] = attestedKey
		}
		if app != nil {
			claims["packages"] = app.packages
			claims["signerDigests"] = app.signatureDigest
		}
		if result.anchor.hasSubjectSerial {
			claims["attestationRootSerial"] = result.anchor.subjectSerialNumber
		}
		return Result{OK: true, Claims: claims}, nil
	}, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
