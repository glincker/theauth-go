package attest

import (
	"encoding/hex"
	"errors"
)

// Android Keystore key attestation schema, ported from the TypeScript parser. See
// https://source.android.com/docs/security/features/keystore/attestation#schema

const (
	// oidKeyAttestation is the key attestation extension.
	oidKeyAttestation = "1.3.6.1.4.1.11129.2.1.17"
	// oidProvisioningInfo is the provisioning information extension of Remote Key Provisioning chains.
	oidProvisioningInfo = "1.3.6.1.4.1.11129.2.1.30"
)

// Security levels and verified boot states, as the strings the TypeScript verifier reports.
const (
	LevelSoftware           = "software"
	LevelTrustedEnvironment = "trusted_environment"
	LevelStrongBox          = "strongbox"

	BootVerified   = "verified"
	BootSelfSigned = "self_signed"
	BootUnverified = "unverified"
	BootFailed     = "failed"
)

var (
	securityLevels = []string{LevelSoftware, LevelTrustedEnvironment, LevelStrongBox}
	bootStates     = []string{BootVerified, BootSelfSigned, BootUnverified, BootFailed}
)

type rootOfTrust struct {
	verifiedBootKey   string
	deviceLocked      bool
	verifiedBootState string
}

type applicationID struct {
	packages        []string
	signatureDigest []string
}

type authorizationList struct {
	origin       *int64
	rootOfTrust  *rootOfTrust
	osVersion    *int64
	osPatchLevel *int64
	application  *applicationID
}

type keyDescription struct {
	attestationVersion       int64
	attestationSecurityLevel string
	keymasterVersion         int64
	keymasterSecurityLevel   string
	attestationChallenge     []byte
	softwareEnforced         authorizationList
	hardwareEnforced         authorizationList
}

func levelOf(t tlv) (string, error) {
	n, err := intOf(t)
	if err != nil {
		return "", err
	}
	if n < 0 || n >= int64(len(securityLevels)) {
		return "", errors.New("unknown security level")
	}
	return securityLevels[n], nil
}

// innerOf returns the single child of an EXPLICIT context tag.
func innerOf(t tlv) (tlv, error) {
	kids, err := children(t)
	if err != nil {
		return tlv{}, err
	}
	if len(kids) != 1 {
		return tlv{}, errors.New("bad explicit tag")
	}
	return kids[0], nil
}

func parseRootOfTrust(t tlv) (*rootOfTrust, error) {
	kids, err := children(t)
	if err != nil {
		return nil, err
	}
	if len(kids) < 3 {
		return nil, errors.New("short RootOfTrust")
	}
	state, err := intOf(kids[2])
	if err != nil {
		return nil, err
	}
	if state < 0 || state >= int64(len(bootStates)) {
		return nil, errors.New("unknown verified boot state")
	}
	locked, err := boolOf(kids[1])
	if err != nil {
		return nil, err
	}
	return &rootOfTrust{
		verifiedBootKey: hex.EncodeToString(kids[0].content), deviceLocked: locked,
		verifiedBootState: bootStates[state],
	}, nil
}

func parseApplicationID(octets tlv) (*applicationID, error) {
	top, err := parseOne(octets.content)
	if err != nil {
		return nil, err
	}
	kids, err := children(top)
	if err != nil {
		return nil, err
	}
	if len(kids) < 2 {
		return nil, errors.New("short AttestationApplicationId")
	}
	pkgs, err := children(kids[0])
	if err != nil {
		return nil, err
	}
	out := &applicationID{packages: []string{}, signatureDigest: []string{}}
	for _, p := range pkgs {
		pk, err := children(p)
		if err != nil {
			return nil, err
		}
		if len(pk) < 2 {
			return nil, errors.New("short AttestationPackageInfo")
		}
		name, err := stringOf(pk[0])
		if err != nil {
			return nil, err
		}
		if _, err := intOf(pk[1]); err != nil {
			return nil, err
		}
		out.packages = append(out.packages, name)
	}
	sigs, err := children(kids[1])
	if err != nil {
		return nil, err
	}
	for _, s := range sigs {
		out.signatureDigest = append(out.signatureDigest, hex.EncodeToString(s.content))
	}
	return out, nil
}

// parseAuthorizationList parses an AuthorizationList. Tags this verifier does not report are
// still read, so a malformed value in any of them refuses the attestation as it does in the
// TypeScript parser.
func parseAuthorizationList(seq tlv) (authorizationList, error) {
	var out authorizationList
	entries, err := children(seq)
	if err != nil {
		return out, err
	}
	for _, entry := range entries {
		if entry.cls != 2 {
			continue
		}
		v, err := innerOf(entry)
		if err != nil {
			return out, err
		}
		switch entry.tag {
		case 1:
			kids, err := children(v)
			if err != nil {
				return out, err
			}
			for _, k := range kids {
				if _, err := intOf(k); err != nil {
					return out, err
				}
			}
		case 2, 3, 10, 718, 719:
			if _, err := intOf(v); err != nil {
				return out, err
			}
		case 702:
			n, err := intOf(v)
			if err != nil {
				return out, err
			}
			out.origin = &n
		case 704:
			if out.rootOfTrust, err = parseRootOfTrust(v); err != nil {
				return out, err
			}
		case 705:
			n, err := intOf(v)
			if err != nil {
				return out, err
			}
			out.osVersion = &n
		case 706:
			n, err := intOf(v)
			if err != nil {
				return out, err
			}
			out.osPatchLevel = &n
		case 709:
			if out.application, err = parseApplicationID(v); err != nil {
				return out, err
			}
		case 710, 711, 712, 713, 716, 717:
			if isUniversal(v, tagOctetString) {
				if _, err := stringOf(v); err != nil {
					return out, err
				}
			}
		}
	}
	return out, nil
}

// parseKeyDescription parses the value of the key attestation extension.
func parseKeyDescription(extensionValue []byte) (*keyDescription, error) {
	top, err := parseOne(extensionValue)
	if err != nil {
		return nil, err
	}
	f, err := children(top)
	if err != nil {
		return nil, err
	}
	if len(f) < 8 {
		return nil, errors.New("short KeyDescription")
	}
	ver, lvl, kmVer, kmLvl, challenge, uniqueID, sw, hw := f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]
	if !isUniversal(challenge, tagOctetString) || !isUniversal(uniqueID, tagOctetString) {
		return nil, errors.New("bad KeyDescription challenge or uniqueId")
	}
	kd := &keyDescription{attestationChallenge: challenge.content}
	if kd.attestationVersion, err = intOf(ver); err != nil {
		return nil, err
	}
	if kd.attestationSecurityLevel, err = levelOf(lvl); err != nil {
		return nil, err
	}
	if kd.keymasterVersion, err = intOf(kmVer); err != nil {
		return nil, err
	}
	if kd.keymasterSecurityLevel, err = levelOf(kmLvl); err != nil {
		return nil, err
	}
	if kd.softwareEnforced, err = parseAuthorizationList(sw); err != nil {
		return nil, err
	}
	if kd.hardwareEnforced, err = parseAuthorizationList(hw); err != nil {
		return nil, err
	}
	return kd, nil
}
