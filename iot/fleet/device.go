package fleet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/iot/device"
)

// ErrOffline is returned by every network call of an offline device.
var ErrOffline = errors.New("fleet: device is offline")

// Device is one simulated device: it holds its own key, clock offset and last accepted bundle, talks
// to the real handlers while online, and decides from its stored bundle while offline.
type Device struct {
	Index int
	ID    string
	// Skew is the device clock minus the server clock. Positive means the device runs fast.
	Skew time.Duration
	// BundleToken and SnapshotToken are the last bundle and revocation snapshot fetched, verified or not.
	BundleToken   string
	SnapshotToken string
	// LastSeq and LastSnapshotSeq are the highest sequence numbers accepted, for rollback protection.
	LastSeq         int64
	LastSnapshotSeq int64
	// Claims are the claims of the last bundle that verified.
	Claims *device.Claims

	fleet   *Fleet
	online  bool
	key     *ecdsa.PrivateKey
	signer  *device.Signer
	thumb   string
	jwkJSON []byte
}

func newDevice(i int, f *Fleet) *Device { return &Device{Index: i, fleet: f, online: true} }

// Now is the time as this device sees it.
func (d *Device) Now() time.Time { return d.fleet.Clock.Now().Add(d.Skew) }

// GoOffline cuts the device from the server. GoOnline restores it.
func (d *Device) GoOffline() { d.online = false }

// GoOnline restores the network.
func (d *Device) GoOnline() { d.online = true }

// SetSkew sets the device clock minus the server clock.
func (d *Device) SetSkew(skew time.Duration) { d.Skew = skew }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jws signs a compact JWS with the device key (ES256).
func (d *Device) jws(typ string, claims map[string]any) (string, error) {
	h, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": typ})
	p, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(p)
	digest := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, d.key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + b64(sig), nil
}

func (d *Device) post(ctx context.Context, path string, form url.Values, jsonBody any, headers map[string]string) (int, []byte, error) {
	if !d.online {
		return 0, nil, ErrOffline
	}
	var body io.Reader
	ctype := ""
	switch {
	case form != nil:
		body, ctype = strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"
	case jsonBody != nil:
		b, _ := json.Marshal(jsonBody)
		body, ctype = bytes.NewReader(b), "application/json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.fleet.srv.URL+path, body)
	if err != nil {
		return 0, nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return d.do(req)
}

// address is the synthetic client address of this device, one per index (10.0.0.0/8 holds 16 million).
func (d *Device) address() string {
	i := d.Index + 1
	return fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
}

func (d *Device) do(req *http.Request) (int, []byte, error) {
	req.Header.Set("X-Forwarded-For", d.address())
	resp, err := d.fleet.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, err
}

// Enroll generates an ES256 key and enrolls with a bulk join token through the real routes: challenge,
// proof of possession, enroll.
func (d *Device) Enroll(ctx context.Context, joinToken string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	d.key = key
	x, y := make([]byte, 32), make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	d.jwkJSON, _ = json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "x": b64(x), "y": b64(y)})
	if d.signer, err = device.NewSigner(key, nil); err != nil {
		return err
	}
	d.thumb = d.signer.Public().KID
	status, raw, err := d.post(ctx, "/oauth/devices/challenge", nil, map[string]any{"join_token": joinToken, "jwk": json.RawMessage(d.jwkJSON)}, nil)
	if err != nil {
		return err
	}
	var ch struct {
		Challenge string `json:"challenge"`
		Nonce     string `json:"nonce"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &ch) != nil || ch.Nonce == "" {
		return fmt.Errorf("challenge answered %d", status)
	}
	now := d.fleet.Clock.Now()
	proof, err := d.jws("device-enroll+jwt", map[string]any{"aud": Issuer, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": ch.Nonce})
	if err != nil {
		return err
	}
	status, raw, err = d.post(ctx, "/oauth/devices/enroll", nil, map[string]any{
		"join_token": joinToken, "jwk": json.RawMessage(d.jwkJSON), "challenge": ch.Challenge, "proof": proof,
		"name": fmt.Sprintf("sim-%d", d.Index),
	}, nil)
	if err != nil {
		return err
	}
	var out struct {
		DeviceID string `json:"device_id"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &out) != nil || out.DeviceID == "" {
		return fmt.Errorf("enroll answered %d: %s", status, raw)
	}
	d.ID = out.DeviceID
	return nil
}

// assertion is an RFC 7523 assertion for the token endpoint, stamped with the device clock.
func (d *Device) assertion(audience string) (string, error) {
	return d.signer.SignAssertion(d.ID, d.Now(), device.AssertionOptions{Audience: audience})
}

// TokenResult is the answer of the token endpoint.
type TokenResult struct {
	Status int
	// OK is true for a 200 with an access token.
	OK bool
	// Error is the OAuth error code of a refusal, such as invalid_scope or invalid_grant.
	Error string
}

// Token asks the token endpoint for an access token for scope with the device assertion grant. It needs
// the network.
func (d *Device) Token(ctx context.Context, scope string) (TokenResult, error) {
	a, err := d.assertion(Issuer + "/oauth/token")
	if err != nil {
		return TokenResult{}, err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {a}, "scope": {scope}}
	status, raw, err := d.post(ctx, "/oauth/token", form, nil, nil)
	if err != nil {
		return TokenResult{}, err
	}
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	_ = json.Unmarshal(raw, &body)
	return TokenResult{Status: status, OK: status == http.StatusOK && body.AccessToken != "", Error: body.Error}, nil
}

// FetchBundle fetches a fresh bundle and snapshot (needs the network) and stores them without
// verifying them. It returns the HTTP status.
func (d *Device) FetchBundle(ctx context.Context) (int, error) {
	if !d.online {
		return 0, ErrOffline
	}
	a, err := d.assertion(Issuer + "/oauth/token")
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.fleet.srv.URL+"/device/bundle", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+a)
	status, raw, err := d.do(req)
	if err != nil {
		return 0, err
	}
	if status == http.StatusOK {
		var body struct {
			Token       string `json:"token"`
			Revocations struct {
				Token string `json:"token"`
			} `json:"revocations"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return status, err
		}
		d.BundleToken, d.SnapshotToken = body.Token, body.Revocations.Token
	}
	return status, nil
}

// VerifyBundle verifies the stored bundle the way a device must: with its own clock, the last accepted
// sequence numbers and the revocation snapshot. On success the sequence numbers move forward. The error
// is a *device.VerifyError.
func (d *Device) VerifyBundle(maxSnapshotAge time.Duration) (*device.Claims, error) {
	if d.BundleToken == "" {
		return nil, &device.VerifyError{Reason: device.ReasonInvalid, Message: "no bundle"}
	}
	claims, err := device.VerifyBundle(d.BundleToken, device.VerifyOptions{
		Keys: d.fleet.bundleKeys, DeviceID: d.ID, LastSeq: d.LastSeq, Now: d.Now(),
		Revocations: &device.RevocationOptions{Token: d.SnapshotToken, MaxAge: maxSnapshotAge, LastSeq: d.LastSnapshotSeq},
	})
	if err != nil {
		return nil, err
	}
	d.Claims, d.LastSeq = claims, claims.Seq
	if seq, ok := snapshotSeq(d.SnapshotToken); ok {
		d.LastSnapshotSeq = seq
	}
	return claims, nil
}

// snapshotSeq reads the seq out of a snapshot the device has just verified.
func snapshotSeq(token string) (int64, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, false
	}
	var c struct {
		Seq int64 `json:"seq"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return 0, false
	}
	return c.Seq, true
}

// OfflineDecision is a decision made with no network.
type OfflineDecision struct {
	device.Decision
	// Verified is false when the bundle or snapshot could not be verified, so nothing was evaluated
	// (fail closed).
	Verified bool
}

// DecideOffline verifies the stored bundle again, then evaluates it. An unverifiable bundle is a denial.
func (d *Device) DecideOffline(action, resource string, maxSnapshotAge time.Duration) OfflineDecision {
	claims, err := d.VerifyBundle(maxSnapshotAge)
	if err != nil {
		return OfflineDecision{Decision: device.Decision{Code: device.CodeDeviceExpired, Reason: err.Error()}}
	}
	return OfflineDecision{Decision: device.Evaluate(claims, action, resource, device.WithNow(d.Now())), Verified: true}
}
