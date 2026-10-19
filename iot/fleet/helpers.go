package fleet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/iot/device"
)

func newULID() theauth.ULID { return ulid.New() }

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return h[7:]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// deviceKeyFor finds the device named by the assertion's iss in the server's store and returns its id
// and public key. Revoked, suspended and unknown devices return errNoDevice.
func (f *Fleet) deviceKeyFor(ctx context.Context, token string) (string, device.PublicKey, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", device.PublicKey{}, errNoDevice
	}
	raw, err := decodeSegment(parts[1])
	if err != nil {
		return "", device.PublicKey{}, errNoDevice
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(raw, &c) != nil || c.Iss == "" {
		return "", device.PublicKey{}, errNoDevice
	}
	id, err := parseULID(c.Iss)
	if err != nil {
		return "", device.PublicKey{}, errNoDevice
	}
	dev, err := f.store.DeviceByID(ctx, id)
	if err != nil || !dev.Active() {
		return "", device.PublicKey{}, errNoDevice
	}
	// The stored JWK carries no kid. Give it its RFC 7638 thumbprint, the kid a device signs into its header.
	var jwk map[string]any
	if json.Unmarshal(dev.PublicKeyJWK, &jwk) != nil {
		return "", device.PublicKey{}, errNoDevice
	}
	jwk["kid"] = "probe"
	set, err := device.ParseJWKS(mustJSON(map[string]any{"keys": []any{jwk}}))
	if err != nil {
		return "", device.PublicKey{}, errNoDevice
	}
	pk, ok := set.Lookup("probe")
	if !ok {
		return "", device.PublicKey{}, errNoDevice
	}
	pk.KID = pk.Thumbprint()
	return dev.ID.String(), pk, nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func decodeSegment(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func parseULID(s string) (theauth.ULID, error) {
	var z theauth.ULID
	if err := z.UnmarshalText([]byte(s)); err != nil {
		return theauth.ULID{}, err
	}
	return z, nil
}
