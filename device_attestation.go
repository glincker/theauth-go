package theauth

import (
	"github.com/glincker/theauth-go/v2/iot/attest"
	"github.com/glincker/theauth-go/v2/iot/device"
)

// DeviceAttestationFacts projects the verified attestation claims stored on a device (Device.AttestationClaims)
// into the facts policy reads: securityLevel (software, hardware or strongbox), bootState and the attested
// app ids. Put the result in device.Claims.Attestation before signing an offline bundle (device.Signer.SignBundle),
// and permissions with an attestation constraint are then decided against it offline, exactly as the
// TypeScript SDK decides them. The second result is false for a device without hardware evidence and for
// claims of a format this SDK does not know (a custom verifier's): such a device satisfies no attestation
// constraint.
func DeviceAttestationFacts(d Device) (device.AttestationFacts, bool) {
	if len(d.AttestationClaims) == 0 {
		return device.AttestationFacts{}, false
	}
	return attest.FactsFromClaims(d.AttestationClaims)
}
