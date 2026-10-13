package as_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2"
)

// e2e_device_ratelimit_test.go: per device budgets on the challenge, enroll
// and assertion grant endpoints.

func TestDeviceTokenRateLimitPerDevice(t *testing.T) {
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{TokenPerMinute: 2})
	k1, k2 := newES256DevKey(t), newES256DevKey(t)
	d1 := h.enrolled(t, k1, theauth.CreateDeviceJoinTokenInput{})
	d2 := h.enrolled(t, k2, theauth.CreateDeviceJoinTokenInput{})

	for i := 0; i < 2; i++ {
		if code, body := h.token(t, h.assertion(t, k1, d1, nil), nil, ""); code != http.StatusOK {
			t.Fatalf("grant %d: %d %v", i, code, body)
		}
	}
	// A limited assertion is not spent: the rejection comes before the jti.
	spare := h.assertion(t, k1, d1, nil)
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {spare}}
	resp, err := http.PostForm(h.srv.URL+"/oauth/token", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("third grant: %d retry-after=%q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	// Another device is unaffected by the first one's budget.
	if code, body := h.token(t, h.assertion(t, k2, d2, nil), nil, ""); code != http.StatusOK {
		t.Fatalf("other device: %d %v", code, body)
	}
}

func TestDeviceAssertionWithBadSignatureDoesNotSpendBudget(t *testing.T) {
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{TokenPerMinute: 1})
	key, other := newES256DevKey(t), newES256DevKey(t)
	devID := h.enrolled(t, key, theauth.CreateDeviceJoinTokenInput{})
	// Forged assertions naming the device must not lock the real one out.
	for i := 0; i < 5; i++ {
		if code, _ := h.token(t, h.assertion(t, other, devID, nil), nil, ""); code != http.StatusBadRequest {
			t.Fatalf("forged assertion: %d", code)
		}
	}
	if code, body := h.token(t, h.assertion(t, key, devID, nil), nil, ""); code != http.StatusOK {
		t.Fatalf("real device after forgeries: %d %v", code, body)
	}
}

func TestDeviceEnrollRateLimitPerJoinToken(t *testing.T) {
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{EnrollPerMinute: 2})
	_, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{})
	key := newES256DevKey(t)
	for i := 0; i < 2; i++ {
		if code, _ := h.challenge(t, secret, key); code != http.StatusOK {
			t.Fatalf("challenge %d: %d", i, code)
		}
	}
	code, _ := h.challenge(t, secret, key)
	if code != http.StatusTooManyRequests {
		t.Fatalf("third challenge: %d, want 429", code)
	}
	// Unknown tokens never reach the budget: they are plain invalid_grant.
	if code, _ := h.challenge(t, "dj_"+strings.Repeat("a", 20), key); code != http.StatusBadRequest {
		t.Fatalf("unknown token: %d, want 400", code)
	}
	// A different join token has its own budget.
	_, other := h.mint(t, theauth.CreateDeviceJoinTokenInput{})
	if code, _ := h.challenge(t, other, key); code != http.StatusOK {
		t.Fatalf("other token: %d", code)
	}
}

func TestDeviceRateLimitCanBeDisabled(t *testing.T) {
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{TokenPerMinute: -1})
	key := newES256DevKey(t)
	devID := h.enrolled(t, key, theauth.CreateDeviceJoinTokenInput{})
	for i := 0; i < 15; i++ {
		if code, body := h.token(t, h.assertion(t, key, devID, nil), nil, ""); code != http.StatusOK {
			t.Fatalf("grant %d: %d %v", i, code, body)
		}
	}
}
