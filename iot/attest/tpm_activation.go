package attest

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
)

// Server side TPM2_MakeCredential, the first half of the credential activation handshake (TCG TPM 2.0
// Library, Part 1 section 24 "Credential Protection", Part 3 section 12.6). The Go twin of the
// TypeScript tpm2MakeCredential.
//
// The server wraps a secret so that only the TPM holding the endorsement key (EK) with the attestation
// key (AK) of this exact name loaded can recover it, through TPM2_ActivateCredential. A device that
// returns the secret proved its AK and its EK live in one TPM, which a quote alone does not show.
//
//  1. A seed is protected to the EK: RSA-OAEP with label "IDENTITY\0" (RSA EK), or an ephemeral ECDH
//     with KDFe label "IDENTITY" (ECC EK).
//  2. symKey = KDFa(nameAlg, seed, "STORAGE", akName, "", symBits), hmacKey = KDFa(nameAlg, seed,
//     "INTEGRITY", "", "", hashBits).
//  3. encIdentity = AES-CFB(symKey, iv 0, TPM2B_DIGEST(secret)), integrity = HMAC(hmacKey, encIdentity || akName).
//  4. credentialBlob = TPM2B_ID_OBJECT { TPM2B_DIGEST(integrity) || encIdentity }.
//
// Checked against a real TPM: docs-local/tpm2/check.sh feeds the output to TPM2_ActivateCredential on a
// software TPM (swtpm) and compares the recovered secret.

// MadeCredential is the output of MakeCredential.
type MadeCredential struct {
	// CredentialBlob is TPM2B_ID_OBJECT, the credentialBlob input of TPM2_ActivateCredential.
	CredentialBlob []byte
	// EncryptedSecret is TPM2B_ENCRYPTED_SECRET, the secret input of TPM2_ActivateCredential.
	EncryptedSecret []byte
}

// MakeCredentialRandomness lets a known answer test pin what MakeCredential draws. Leave it nil in
// production.
type MakeCredentialRandomness struct {
	// Seed is the RSA EK seed (digest sized). Ignored for an ECC EK.
	Seed []byte
	// Ephemeral is the ECC EK ephemeral key.
	Ephemeral *ecdh.PrivateKey
}

func hmacOf(hash crypto.Hash, key, data []byte) []byte {
	m := hmac.New(hash.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func u32be(n uint32) []byte { return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)} }

func nulTerminated(s string) []byte { return append([]byte(s), 0) }

// tpmKDFa is KDFa, SP 800-108 counter mode with HMAC (Part 1 section 11.4.10.2). bits is the output length.
func tpmKDFa(hash crypto.Hash, key []byte, label string, contextU, contextV []byte, bits int) []byte {
	var out []byte
	need := (bits + 7) / 8
	for i := uint32(1); len(out) < need; i++ {
		out = append(out, hmacOf(hash, key, concat(u32be(i), nulTerminated(label), contextU, contextV, u32be(uint32(bits))))...)
	}
	return out[:need]
}

// tpmKDFe is KDFe, the SP 800-56A concatenation KDF (Part 1 section 11.4.10.3).
func tpmKDFe(hash crypto.Hash, z []byte, label string, partyU, partyV []byte, bits int) []byte {
	var out []byte
	need := (bits + 7) / 8
	for i := uint32(1); len(out) < need; i++ {
		out = append(out, hashBytes(hash, concat(u32be(i), z, nulTerminated(label), partyU, partyV))...)
	}
	return out[:need]
}

func sizedBytes(b []byte) []byte { return concat([]byte{byte(len(b) >> 8), byte(len(b))}, b) }

// tpmObjectName is the name of a TPM object: nameAlg then the digest of its TPMT_PUBLIC (Part 1 section 16).
func tpmObjectName(pub *tpmPublic) ([]byte, error) {
	alg, ok := hashByAlg[pub.nameAlg]
	if !ok {
		return nil, reasonErr("Unsupported name algorithm")
	}
	return concat([]byte{byte(pub.nameAlg >> 8), byte(pub.nameAlg)}, digestNamed(alg, pub.raw)), nil
}

// ObjectName returns the TPM name (hex) of a TPMT_PUBLIC or TPM2B_PUBLIC. It is how a caller learns
// the AK name to give MakeCredential.
func ObjectName(public []byte) ([]byte, error) {
	pub, err := parseTPMPublicOpts(public, true)
	if err != nil {
		return nil, err
	}
	return tpmObjectName(pub)
}

func checkEK(pub *tpmPublic) (crypto.Hash, error) {
	name, ok := hashByAlg[pub.nameAlg]
	const need = attrRestricted | attrDecrypt | attrFixedTPM | attrFixedParent
	if !ok || name == "sha1" || pub.attributes&need != need || pub.attributes&attrSign != 0 {
		return 0, reasonErr("Endorsement key is not a restricted, TPM resident decryption key with SHA-256 or stronger")
	}
	if pub.isRSA && (pub.rsaBit < 2048 || bigOf(pub.rsaN).BitLen() < 2048) {
		return 0, reasonErr("RSA endorsement key is too small")
	}
	return cryptoHashByName[name], nil
}

// MakeCredential wraps credential for the TPM holding ekPublic (TPMT_PUBLIC or TPM2B_PUBLIC) with the
// key named akName loaded. credential is at most the digest size of the EK name algorithm. random is
// nil outside known answer tests.
func MakeCredential(ekPublic, akName, credential []byte, random *MakeCredentialRandomness) (MadeCredential, error) {
	ek, err := parseTPMPublicOpts(ekPublic, true)
	if err != nil {
		return MadeCredential{}, err
	}
	hash, err := checkEK(ek)
	if err != nil {
		return MadeCredential{}, err
	}
	hashLen := hash.Size()
	if len(credential) < 1 || len(credential) > hashLen {
		return MadeCredential{}, reasonErr(fmt.Sprintf("The credential must be between 1 and %d bytes", hashLen))
	}
	var seed, encrypted []byte
	switch {
	case ek.isRSA:
		seed = make([]byte, hashLen)
		if random != nil && random.Seed != nil {
			seed = random.Seed
		} else if _, err := rand.Read(seed); err != nil {
			return MadeCredential{}, err
		}
		pub := &rsa.PublicKey{N: bigOf(ek.rsaN), E: int(ek.rsaE)}
		enc, err := rsa.EncryptOAEP(hash.New(), rand.Reader, pub, seed, nulTerminated("IDENTITY"))
		if err != nil {
			return MadeCredential{}, err
		}
		encrypted = sizedBytes(enc)
	default:
		var curve ecdh.Curve
		switch ek.curve {
		case "P-256":
			curve = ecdh.P256()
		case "P-384":
			curve = ecdh.P384()
		case "P-521":
			curve = ecdh.P521()
		default:
			return MadeCredential{}, reasonErr("Unsupported endorsement key type")
		}
		size := curveSize(ek.curve)
		if len(ek.eccX) != size || len(ek.eccY) != size {
			return MadeCredential{}, errors.New("bad point")
		}
		peer, err := curve.NewPublicKey(concat([]byte{4}, ek.eccX, ek.eccY))
		if err != nil {
			return MadeCredential{}, err
		}
		eph := (*ecdh.PrivateKey)(nil)
		if random != nil {
			eph = random.Ephemeral
		}
		if eph == nil {
			if eph, err = curve.GenerateKey(rand.Reader); err != nil {
				return MadeCredential{}, err
			}
		}
		z, err := eph.ECDH(peer)
		if err != nil {
			return MadeCredential{}, err
		}
		point := eph.PublicKey().Bytes()
		ex, ey := point[1:1+size], point[1+size:]
		seed = tpmKDFe(hash, z, "IDENTITY", ex, ek.eccX, hashLen*8)
		encrypted = sizedBytes(concat(sizedBytes(ex), sizedBytes(ey)))
	}
	symKey := tpmKDFa(hash, seed, "STORAGE", akName, nil, 128)
	hmacKey := tpmKDFa(hash, seed, "INTEGRITY", nil, nil, hashLen*8)
	block, err := aes.NewCipher(symKey)
	if err != nil {
		return MadeCredential{}, err
	}
	plain := sizedBytes(credential)
	encIdentity := make([]byte, len(plain))
	cipher.NewCFBEncrypter(block, make([]byte, aes.BlockSize)).XORKeyStream(encIdentity, plain)
	integrity := hmacOf(hash, hmacKey, concat(encIdentity, akName))
	return MadeCredential{CredentialBlob: sizedBytes(concat(sizedBytes(integrity), encIdentity)), EncryptedSecret: encrypted}, nil
}

// activationLabel separates the activation secret from every other use of a key.
const activationLabel = "theauth/device/tpm2-activation/v1"

// DeriveActivationSecret is the stateless activation secret of one enrollment: HMAC-SHA-256 over the
// enrollment nonce and the names of the AK and EK, keyed by key (a server secret). The server wraps
// it with MakeCredential and the TPM2 certify verifier recomputes it, so no activation state is stored
// and a secret cannot be used for another enrollment, AK or EK.
func DeriveActivationSecret(key []byte, nonce string, akName, ekName []byte) []byte {
	return hmacOf(crypto.SHA256, key, concat(nulTerminated(activationLabel), sizedBytes([]byte(nonce)), sizedBytes(akName), sizedBytes(ekName)))
}
