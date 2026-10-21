package as

// iotdevice_tpm.go is the server half of the TPM 2.0 credential activation (TPM2_MakeCredential)
// that the attest.NewTPM2CertifyVerifier needs. The secret is derived, not stored: HMAC of the
// enrollment nonce, the AK name and the EK name under a key derived from the AS encryption key, so
// the verifier recomputes it and no activation state exists. A secret made for one enrollment, AK or
// EK is worthless for another.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/iot/attest"
)

// tpmActivationKeyLabel separates the activation key from every other key derived from the AS
// encryption key.
const tpmActivationKeyLabel = "theauth/device/tpm2-activation-key/v1"

// tpmActivationKey is the server secret behind DeriveActivationSecret. Enrollment hands it to the TPM
// certify verifier in attest.Input.ActivationKey.
func (s *Service) tpmActivationKey() []byte {
	m := hmac.New(sha256.New, s.encryptionKey)
	m.Write([]byte(tpmActivationKeyLabel))
	return m.Sum(nil)
}

// DeviceTPMActivationRequest asks for a TPM credential activation during enrollment. It carries the
// enrollment fields (join token, device key, challenge, proof of possession) plus the TPM keys.
type DeviceTPMActivationRequest struct {
	DeviceEnrollRequest
	// EKPublic and AKPublic are TPMT_PUBLIC or TPM2B_PUBLIC as base64url.
	EKPublic string
	AKPublic string
}

// DeviceTPMActivation is the TPM2_ActivateCredential input the device needs.
type DeviceTPMActivation struct {
	// CredentialBlob is TPM2B_ID_OBJECT as base64url.
	CredentialBlob string `json:"credential_blob"`
	// EncryptedSecret is TPM2B_ENCRYPTED_SECRET as base64url.
	EncryptedSecret string `json:"encrypted_secret"`
}

// DeviceTPMActivation wraps a secret for the device's EK and AK. It checks what EnrollDevice checks
// before it spends anything (join token, challenge, proof of possession) and spends nothing itself.
// The device runs TPM2_ActivateCredential and sends the recovered secret in its attestation evidence
// as activation.secret.
func (s *Service) DeviceTPMActivation(ctx context.Context, req DeviceTPMActivationRequest) (DeviceTPMActivation, error) {
	store, ok := s.identityStore()
	if !ok {
		return DeviceTPMActivation{}, models.ErrDevicesDisabled
	}
	key, err := parseDeviceKey(req.JWK)
	if err != nil {
		return DeviceTPMActivation{}, models.ErrDeviceEnrollmentInvalid
	}
	att, err := s.attestDevice(ctx, store, req.DeviceEnrollRequest, key)
	if err != nil {
		return DeviceTPMActivation{}, err
	}
	if err := s.deviceLimit(ctx, "activation", att.Subject, s.Cfg.DeviceTokens.EnrollPerMinute); err != nil {
		return DeviceTPMActivation{}, err
	}
	now := s.now().UTC()
	ch, err := jwt.VerifyWith(req.Challenge, s.VerificationKey, challengeTyp, s.Cfg.Issuer, now,
		jwt.VerifyOptions{Skew: s.Cfg.ClockSkew})
	if err != nil || ch.Sub != att.Subject {
		return DeviceTPMActivation{}, models.ErrDeviceEnrollmentInvalid
	}
	if jkt, _ := ch.Extra["jkt"].(string); jkt != key.thumbprint {
		return DeviceTPMActivation{}, models.ErrDeviceEnrollmentInvalid
	}
	if !s.verifyEnrollProof(req.Proof, key, ch.Jti, now) {
		return DeviceTPMActivation{}, models.ErrDeviceEnrollmentInvalid
	}
	if cfg := s.Cfg.DeviceTokens.Attestation; cfg == nil || cfg.Verify == nil {
		return DeviceTPMActivation{}, &DeviceAttestationError{Reason: "No attestation verifier is configured"}
	}
	ekPub, err1 := base64.RawURLEncoding.DecodeString(trimPad(req.EKPublic))
	akPub, err2 := base64.RawURLEncoding.DecodeString(trimPad(req.AKPublic))
	if err1 != nil || err2 != nil {
		return DeviceTPMActivation{}, &DeviceAttestationError{Reason: "TPM keys are not base64url"}
	}
	akName, err1 := attest.ObjectName(akPub)
	ekName, err2 := attest.ObjectName(ekPub)
	if err1 != nil || err2 != nil {
		return DeviceTPMActivation{}, &DeviceAttestationError{Reason: "TPM keys are not valid"}
	}
	secret := attest.DeriveActivationSecret(s.tpmActivationKey(), ch.Jti, akName, ekName)
	made, err := attest.MakeCredential(ekPub, akName, secret, nil)
	if err != nil {
		return DeviceTPMActivation{}, &DeviceAttestationError{Reason: err.Error()}
	}
	return DeviceTPMActivation{
		CredentialBlob:  base64.RawURLEncoding.EncodeToString(made.CredentialBlob),
		EncryptedSecret: base64.RawURLEncoding.EncodeToString(made.EncryptedSecret),
	}, nil
}

func trimPad(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}
