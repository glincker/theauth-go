package as_test

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// e2e_device_registry_test.go: claim codes, bulk enrollment tokens and suspend and resume, through
// the real AS handlers.

var claimCodeRE = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$`)

func TestDeviceClaimCodeEnrollsOneDevice(t *testing.T) {
	h := newIoTHarness(t, nil)
	tok, code := h.mint(t, theauth.CreateDeviceJoinTokenInput{Kind: theauth.DeviceJoinTokenClaim, Name: "porch"})
	if !claimCodeRE.MatchString(code) {
		t.Fatalf("claim code %q has the wrong shape", code)
	}
	if tok.MaxUses != 1 || time.Until(tok.ExpiresAt) > 16*time.Minute || time.Until(tok.ExpiresAt) < 14*time.Minute {
		t.Fatalf("claim token defaults: max uses %d, expires in %v", tok.MaxUses, time.Until(tok.ExpiresAt))
	}

	// A person typing the code: lower case, no dash, I and L for 1, O for 0.
	typed := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	typed = strings.NewReplacer("1", "l", "0", "o").Replace(typed)
	if status, body := h.enroll(t, "ZZZZZ-ZZZZZ", newES256DevKey(t)); status != http.StatusBadRequest {
		t.Fatalf("wrong code: %d %v", status, body)
	}
	key := newES256DevKey(t)
	status, body := h.enroll(t, typed, key)
	if status != http.StatusCreated {
		t.Fatalf("enroll with typed code %q: %d %v", typed, status, body)
	}
	if body["name"] != "porch" {
		t.Fatalf("name from the token lost: %v", body)
	}
	if status, _ := h.enroll(t, code, newES256DevKey(t)); status != http.StatusBadRequest {
		t.Fatalf("second use of a claim code: %d", status)
	}
	// The device works like any other.
	if status, tr := h.token(t, h.assertion(t, key, body["device_id"].(string), nil), nil, ""); status != http.StatusOK {
		t.Fatalf("token for claimed device: %d %v", status, tr)
	}
	// A claim code is not a join token: its text cannot be replayed with a dj_ prefix.
	if status, _ := h.enroll(t, "dj_"+code, newES256DevKey(t)); status != http.StatusBadRequest {
		t.Fatalf("dj_ prefixed claim code: %d", status)
	}
}

func TestDeviceBulkTokenEnrollsUpToMaxUses(t *testing.T) {
	h := newIoTHarness(t, nil)
	tok, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{Kind: theauth.DeviceJoinTokenBulk, MaxUses: 3, Name: "line-1"})
	if !strings.HasPrefix(secret, "dj_") || tok.MaxUses != 3 {
		t.Fatalf("bulk token: %+v %q", tok, secret)
	}
	ids := map[string]bool{}
	for i := 0; i < 3; i++ {
		status, body := h.enroll(t, secret, newES256DevKey(t))
		if status != http.StatusCreated {
			t.Fatalf("enroll %d: %d %v", i, status, body)
		}
		ids[body["device_id"].(string)] = true
	}
	if len(ids) != 3 {
		t.Fatalf("device ids not distinct: %v", ids)
	}
	if status, _ := h.enroll(t, secret, newES256DevKey(t)); status != http.StatusBadRequest {
		t.Fatalf("fourth enrollment: %d", status)
	}
	if devs, _ := h.a.ListDevices(context.Background(), &h.org); len(devs) != 3 {
		t.Fatalf("devices = %d, want 3", len(devs))
	}
}

func TestDeviceBulkTokenConcurrentEnrollment(t *testing.T) {
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{EnrollPerMinute: -1})
	_, secret := h.mint(t, theauth.CreateDeviceJoinTokenInput{Kind: theauth.DeviceJoinTokenBulk, MaxUses: 4})
	const workers = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for i := 0; i < workers; i++ {
		key := newES256DevKey(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if status, _ := h.enroll(t, secret, key); status == http.StatusCreated {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 4 {
		t.Fatalf("%d devices enrolled with a 4 use token", won)
	}
	if devs, _ := h.a.ListDevices(context.Background(), &h.org); len(devs) != 4 {
		t.Fatalf("devices = %d, want 4", len(devs))
	}
}

func TestDeviceBulkTokenRefundsOnConflict(t *testing.T) {
	h := newIoTHarness(t, nil)
	// Two single device tokens that fix the same SPIFFE ID: the second enrollment fails at insert
	// and must give its use back.
	_, first := h.mint(t, theauth.CreateDeviceJoinTokenInput{SPIFFEID: "spiffe://example.org/dup"})
	tok, second := h.mint(t, theauth.CreateDeviceJoinTokenInput{SPIFFEID: "spiffe://example.org/dup"})
	if status, _ := h.enroll(t, first, newES256DevKey(t)); status != http.StatusCreated {
		t.Fatal("first enroll failed")
	}
	if status, _ := h.enroll(t, second, newES256DevKey(t)); status != http.StatusConflict {
		t.Fatalf("conflicting enroll: %d", status)
	}
	got, err := h.store.DeviceJoinTokenByID(context.Background(), tok.ID)
	if err != nil || got.Uses != 0 || got.RedeemedAt != nil {
		t.Fatalf("use not refunded: %+v %v", got, err)
	}
}

func TestDeviceCreateJoinTokenValidation(t *testing.T) {
	h := newIoTHarness(t, nil)
	bad := []theauth.CreateDeviceJoinTokenInput{
		{Kind: theauth.DeviceJoinTokenBulk},
		{Kind: theauth.DeviceJoinTokenBulk, MaxUses: 2_000_000},
		{Kind: theauth.DeviceJoinTokenBulk, MaxUses: 5, SPIFFEID: "spiffe://example.org/x"},
		{Kind: theauth.DeviceJoinTokenClaim, MaxUses: 2},
		{MaxUses: 2},
		{Kind: "other"},
		{Kind: theauth.DeviceJoinTokenClaim, TTL: 31 * 24 * time.Hour},
		{Kind: theauth.DeviceJoinTokenBulk, MaxUses: 2, TTL: 31 * 24 * time.Hour},
	}
	for _, in := range bad {
		in.Scopes = []string{"telemetry:write"}
		if _, _, err := h.a.CreateDeviceJoinToken(context.Background(), in); err == nil {
			t.Errorf("accepted %+v", in)
		}
	}
	// A bulk token of one may fix a SPIFFE ID.
	in := theauth.CreateDeviceJoinTokenInput{Kind: theauth.DeviceJoinTokenBulk, MaxUses: 1, SPIFFEID: "spiffe://example.org/one", Scopes: []string{"a"}}
	if _, _, err := h.a.CreateDeviceJoinToken(context.Background(), in); err != nil {
		t.Errorf("bulk of one with a SPIFFE ID: %v", err)
	}
}

func TestDeviceSuspendAndResume(t *testing.T) {
	var mu sync.Mutex
	var changes []string
	h := newIoTHarness(t, &theauth.DeviceTokensConfig{
		OnStatusChange: func(_ context.Context, id, status string) {
			mu.Lock()
			changes = append(changes, status)
			mu.Unlock()
		},
	})
	ctx := context.Background()
	key := newES256DevKey(t)
	devID := h.enrolled(t, key, theauth.CreateDeviceJoinTokenInput{SPIFFEID: "spiffe://example.org/hold"})
	status, tr := h.token(t, h.assertion(t, key, devID, nil), nil, "")
	if status != http.StatusOK {
		t.Fatalf("token: %d %v", status, tr)
	}
	access := tr["access_token"].(string)
	if in := h.introspect(t, access); in["active"] != true {
		t.Fatalf("pre-suspend introspect: %v", in)
	}

	var id theauth.ULID
	if err := id.UnmarshalText([]byte(devID)); err != nil {
		t.Fatal(err)
	}
	if err := h.a.SuspendDevice(ctx, id); err != nil {
		t.Fatalf("SuspendDevice: %v", err)
	}
	if err := h.a.SuspendDevice(ctx, id); err != nil {
		t.Fatalf("second SuspendDevice: %v", err)
	}
	status, body := h.token(t, h.assertion(t, key, devID, nil), nil, "")
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("assertion while suspended: %d %v", status, body)
	}
	if in := h.introspect(t, access); in["active"] != false {
		t.Fatalf("token still active while suspended: %v", in)
	}
	if devs, _ := h.a.ListDevices(ctx, &h.org); len(devs) != 1 || devs[0].Status != theauth.DeviceStatusSuspended || devs[0].RevokedAt != nil {
		t.Fatalf("device record: %+v", devs)
	}

	if err := h.a.ResumeDevice(ctx, id); err != nil {
		t.Fatalf("ResumeDevice: %v", err)
	}
	if status, tr := h.token(t, h.assertion(t, key, devID, nil), nil, ""); status != http.StatusOK {
		t.Fatalf("assertion after resume: %d %v", status, tr)
	}
	if in := h.introspect(t, access); in["active"] != true {
		t.Fatalf("token not active again after resume: %v", in)
	}

	if err := h.a.RevokeDevice(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := h.a.ResumeDevice(ctx, id); err != theauth.ErrDeviceRevoked {
		t.Fatalf("resume a revoked device: %v", err)
	}
	if err := h.a.SuspendDevice(ctx, id); err != theauth.ErrDeviceRevoked {
		t.Fatalf("suspend a revoked device: %v", err)
	}
	if status, _ := h.token(t, h.assertion(t, key, devID, nil), nil, ""); status != http.StatusBadRequest {
		t.Fatal("a revoked device got a token")
	}
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(changes, ","); got != "suspended,suspended,active" {
		t.Fatalf("OnStatusChange saw %q", got)
	}
}
