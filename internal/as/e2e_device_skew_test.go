package as_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// A device clock is rarely exact. With Config.ClockSkew left at zero the device grant still tolerates 30
// seconds, like the TypeScript device module, and refuses a clock minutes off.
func TestDeviceAssertionToleratesSmallClockDrift(t *testing.T) {
	h := newIoTHarness(t, nil)
	key := newES256DevKey(t)
	id := h.enrolled(t, key, theauth.CreateDeviceJoinTokenInput{Name: "drifting"})
	try := func(offset time.Duration) int {
		a := h.assertion(t, key, id, func(o *assertionOpts) {
			o.iat = time.Now().Add(offset)
			o.exp = o.iat.Add(time.Minute)
		})
		code, _ := h.token(t, a, nil, "")
		return code
	}
	for _, off := range []time.Duration{10 * time.Second, -10 * time.Second} {
		if code := try(off); code != http.StatusOK {
			t.Fatalf("clock %v off: %d", off, code)
		}
	}
	for _, off := range []time.Duration{2 * time.Minute, -3 * time.Minute} {
		if code := try(off); code == http.StatusOK {
			t.Fatalf("clock %v off was accepted", off)
		}
	}
}
