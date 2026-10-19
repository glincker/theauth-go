package as

// iotdevice_attest.go is the enrollment hook for hardware attestation evidence. It runs after
// the join token, the challenge and the proof of possession all checked out, and before the join
// token is spent, so refused evidence never costs a use. The verifiers live in iot/attest.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/iot/attest"
)

// DeviceAttestationConfig verifies hardware attestation evidence at enrollment.
type DeviceAttestationConfig struct {
	// Required refuses enrollment without evidence that Verify accepts. When false, a device
	// that sends no evidence still enrolls, and evidence that is sent must pass.
	Required bool
	// Verify checks the evidence. Build one with attest.NewAndroidKeyVerifier,
	// attest.NewAppleAppAttestVerifier or attest.NewTPM2QuoteVerifier, or write your own. The
	// nonce it receives is the enrollment challenge nonce (DeviceChallenge.Nonce), so evidence
	// cannot be replayed from another enrollment. A returned error, a panic and a Result with OK
	// false all refuse the enrollment. Evidence sent while Verify is nil is refused.
	Verify attest.Verifier
}

// DeviceAttestationError is the enrollment refusal for evidence the verifier rejected. It matches
// models.ErrDeviceAttestationFailed with errors.Is.
type DeviceAttestationError struct {
	// Reason is the verifier's refusal sentence, for example "Attestation challenge does not
	// match the enrollment nonce". It is safe to show to the device. Empty when the verifier failed
	// for a reason that is not about the evidence.
	Reason string
}

func (e *DeviceAttestationError) Error() string {
	if e.Reason == "" {
		return models.ErrDeviceAttestationFailed.Error()
	}
	return models.ErrDeviceAttestationFailed.Error() + ": " + e.Reason
}

func (e *DeviceAttestationError) Is(target error) bool {
	return target == models.ErrDeviceAttestationFailed
}

// checkHardwareAttestation returns the verified claims, nil when no evidence was sent and none was
// required.
func (s *Service) checkHardwareAttestation(ctx context.Context, req DeviceEnrollRequest, att DeviceAttestation, key deviceKey, nonce string) (map[string]any, error) {
	cfg := s.Cfg.DeviceTokens.Attestation
	if req.AttestationEvidence == "" {
		if cfg != nil && cfg.Required {
			s.auditAttestationRefusal(ctx, att, "evidence missing")
			return nil, models.ErrDeviceAttestationRequired
		}
		return nil, nil
	}
	if cfg == nil || cfg.Verify == nil {
		s.auditAttestationRefusal(ctx, att, "no verifier configured")
		return nil, &DeviceAttestationError{Reason: "No attestation verifier is configured"}
	}
	res, err := runVerifier(ctx, cfg.Verify, attest.Input{
		Evidence: req.AttestationEvidence, Nonce: nonce, EnrollmentID: att.Subject,
		CredentialKind: "jwk", CredentialKeyThumbprint: key.thumbprint,
	})
	if err != nil {
		slog.Warn("theauth: device attestation verifier failed", "enrollment", att.Subject, "err", err.Error())
		s.auditAttestationRefusal(ctx, att, "verifier failed")
		return nil, &DeviceAttestationError{}
	}
	if !res.OK {
		s.auditAttestationRefusal(ctx, att, res.Reason)
		return nil, &DeviceAttestationError{Reason: res.Reason}
	}
	claims := res.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	return claims, nil
}

// runVerifier calls the verifier and turns a panic into an error, so a bug in a verifier refuses
// the enrollment.
func runVerifier(ctx context.Context, verify attest.Verifier, in attest.Input) (res attest.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = attest.Result{}, fmt.Errorf("verifier panicked: %v", r)
		}
	}()
	res, err = verify(ctx, in)
	if err == nil && !res.OK && res.Reason == "" {
		err = errors.New("verifier refused without a reason")
	}
	return res, err
}

func (s *Service) auditAttestationRefusal(ctx context.Context, att DeviceAttestation, reason string) {
	s.Audit.EmitAudit(ctx, "device.enroll.attestation_refused",
		models.TargetRef{Type: "device_join_token", ID: att.Subject}, map[string]any{"reason": reason})
}
