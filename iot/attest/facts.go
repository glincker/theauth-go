package attest

import (
	"slices"

	"github.com/glincker/theauth-go/v2/iot/device"
)

// FactsFromClaims projects the claims a verifier returned at enrollment into the facts policy
// reads (device.AttestationFacts). It is the Go twin of the TypeScript attestationFacts and is
// replayed from shared vectors. It accepts claims straight from a verifier (typed slices) and
// claims read back from storage (decoded JSON). The second result is false for claims of an
// unknown format, such as a custom verifier's, so they can never satisfy a rule.
//
//   - android-key-attestation: the level is the lower of the attestation and key level, with TEE
//     as hardware. The boot state is the verified boot state, or unlocked when the bootloader is
//     unlocked. App ids are the attested package names.
//   - apple-app-attest: the key lives in the Secure Enclave, so hardware. No boot state. The app
//     id is the claimed appId.
//   - tpm2-quote: hardware only when the attestation key chained to a trusted root, else software.
//   - tpm2-certify: hardware only when the credential was activated and the endorsement key chained to
//     a trusted root (ekVerified), else software.
func FactsFromClaims(claims map[string]any) (device.AttestationFacts, bool) {
	format, _ := claims["format"].(string)
	switch format {
	case "android-key-attestation":
		f := device.AttestationFacts{
			Format:        format,
			SecurityLevel: androidFactLevel(claims["securityLevel"], claims["keySecurityLevel"]),
		}
		bs, _ := claims["verifiedBootState"].(string)
		if locked, ok := claims["deviceLocked"].(bool); ok && !locked {
			f.BootState = device.BootUnlocked
		} else if slices.Contains([]string{device.BootVerified, device.BootSelfSigned, device.BootUnverified, device.BootFailed}, bs) {
			f.BootState = bs
		}
		for _, p := range claimStrings(claims["packages"]) {
			if p != "" {
				f.AppIDs = append(f.AppIDs, p)
			}
		}
		return f, true
	case "apple-app-attest":
		f := device.AttestationFacts{Format: format, SecurityLevel: device.LevelHardware}
		if id, _ := claims["appId"].(string); id != "" {
			f.AppIDs = []string{id}
		}
		return f, true
	case "tpm2-certify":
		f := device.AttestationFacts{Format: format, SecurityLevel: device.LevelSoftware}
		activated, _ := claims["activated"].(bool)
		verified, _ := claims["ekVerified"].(bool)
		if activated && verified {
			f.SecurityLevel = device.LevelHardware
		}
		return f, true
	case "tpm2-quote":
		f := device.AttestationFacts{Format: format, SecurityLevel: device.LevelSoftware}
		if v, _ := claims["akVerified"].(bool); v {
			f.SecurityLevel = device.LevelHardware
		}
		return f, true
	}
	return device.AttestationFacts{}, false
}

func androidFactLevel(attestation, key any) string {
	rank := func(v any) int {
		switch v {
		case "strongbox":
			return 2
		case "trusted_environment":
			return 1
		}
		return 0
	}
	low := rank(attestation)
	if key != nil && rank(key) < low {
		low = rank(key)
	}
	switch low {
	case 2:
		return device.LevelStrongbox
	case 1:
		return device.LevelHardware
	}
	return device.LevelSoftware
}

func claimStrings(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
