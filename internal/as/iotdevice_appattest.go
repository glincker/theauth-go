package as

// iotdevice_appattest.go verifies Apple App Attest assertions from an enrolled device. The key and
// App ID come from the claims stored at enrollment (attestedPublicKey, appId), the counter from the
// device record. After the signature checks the counter moves forward with one conditional update,
// so two requests carrying the same assertion cannot both succeed.

import (
	"context"
	"errors"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/iot/attest"
)

// DeviceAppAssertionRequest is one assertion from a device.
type DeviceAppAssertionRequest struct {
	// Assertion is the object from DCAppAttestService.generateAssertion, base64 or base64url.
	Assertion string
	// ClientData is the exact bytes the app hashed into clientDataHash. Put a server challenge in it
	// and check the challenge yourself: this package keeps no nonce store for assertions, the counter
	// is the replay protection.
	ClientData []byte
}

// Codes of a DeviceAppAssertionError.
const (
	AppAssertionNotFound = "device_not_found"
	AppAssertionBlocked  = "device_blocked"
	AppAssertionNoKey    = "not_app_attest"
	AppAssertionInvalid  = "assertion_invalid"
	AppAssertionReplayed = "assertion_replayed"
	AppAssertionDisabled = "storage_unsupported"
)

// ErrDeviceAppAssertion matches every *DeviceAppAssertionError with errors.Is.
var ErrDeviceAppAssertion = errors.New("theauth: device app attest assertion refused")

// DeviceAppAssertionError is the refusal of an assertion. Code is one of the AppAssertion constants,
// the same strings as the TypeScript codes. Reason is safe to show to the device.
type DeviceAppAssertionError struct {
	Code   string
	Reason string
}

func (e *DeviceAppAssertionError) Error() string {
	return ErrDeviceAppAssertion.Error() + ": " + e.Code + ": " + e.Reason
}

func (e *DeviceAppAssertionError) Is(target error) bool { return target == ErrDeviceAppAssertion }

func (s *Service) refuseAppAssertion(ctx context.Context, d *models.Device, code, reason string) error {
	if d != nil {
		s.Audit.EmitAudit(ctx, "device.app_assertion.refused",
			models.TargetRef{Type: "device", ID: d.ID.String()}, map[string]any{"code": code, "reason": reason})
	}
	return &DeviceAppAssertionError{Code: code, Reason: reason}
}

// VerifyDeviceAppAssertion checks an App Attest assertion against the key attested at enrollment and
// advances the replay counter. It returns the device, or a *DeviceAppAssertionError.
func (s *Service) VerifyDeviceAppAssertion(ctx context.Context, deviceID models.ULID, req DeviceAppAssertionRequest) (models.Device, error) {
	store, ok := s.identityStore()
	counters, hasCounters := s.Storage.(DeviceAppAttestStorage)
	if !ok || !hasCounters {
		return models.Device{}, &DeviceAppAssertionError{Code: AppAssertionDisabled, Reason: "Storage cannot hold an App Attest counter"}
	}
	d, err := store.DeviceByID(ctx, deviceID)
	if err != nil {
		return models.Device{}, &DeviceAppAssertionError{Code: AppAssertionNotFound, Reason: "Device not found"}
	}
	if !d.Active() {
		return models.Device{}, &DeviceAppAssertionError{Code: AppAssertionBlocked, Reason: "Device is " + d.Status}
	}
	format, _ := d.AttestationClaims["format"].(string)
	appID, _ := d.AttestationClaims["appId"].(string)
	key, _ := d.AttestationClaims["attestedPublicKey"].(string)
	if format != "apple-app-attest" || appID == "" || key == "" {
		return models.Device{}, s.refuseAppAssertion(ctx, d, AppAssertionNoKey,
			"Device has no App Attest key (it enrolled without Apple evidence, or before attestedPublicKey was stored)")
	}
	res := attest.VerifyAppleAssertion(attest.AppleAssertionInput{
		Assertion: req.Assertion, ClientData: req.ClientData, AppID: appID, PublicKey: key,
		PreviousCounter: int64(d.AppAttestCounter),
	})
	if !res.OK {
		code := AppAssertionInvalid
		if res.Reason == attest.ReasonAssertionCounter {
			code = AppAssertionReplayed
		}
		return models.Device{}, s.refuseAppAssertion(ctx, d, code, res.Reason)
	}
	// The one writer that moves the counter forward wins. A racing request finds it already raised.
	advanced, err := counters.AdvanceAppAttestCounter(ctx, d.ID, res.Counter)
	if err != nil {
		return models.Device{}, err
	}
	if !advanced {
		return models.Device{}, s.refuseAppAssertion(ctx, d, AppAssertionReplayed, attest.ReasonAssertionCounter)
	}
	d.AppAttestCounter = res.Counter
	return *d, nil
}
