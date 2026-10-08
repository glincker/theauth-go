package as_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

func (h *deviceHarness) registerWith(token, body string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return h.do(req)
}

func TestRegisterWithInitialAccessToken(t *testing.T) {
	ctx := context.Background()
	const agentBody = `{"client_name":"build agent","grant_types":["client_credentials"],"scope":"files.read"}`

	t.Run("a one-time token registers exactly one client", func(t *testing.T) {
		h := newDeviceHarness(t)
		_, raw, err := h.auth.CreateRegistrationToken(ctx, theauth.CreateRegistrationTokenInput{Label: "ci"})
		if err != nil {
			t.Fatal(err)
		}
		code, body := h.registerWith(raw, agentBody)
		if code != http.StatusCreated || body["client_id"] == nil || body["client_secret"] == nil {
			t.Fatalf("first use: %d %v", code, body)
		}
		code, body = h.registerWith(raw, agentBody)
		if code != http.StatusUnauthorized || body["error"] != "access_denied" {
			t.Fatalf("second use: %d %v", code, body)
		}
	})

	t.Run("the token caps scope and grant types without being spent", func(t *testing.T) {
		h := newDeviceHarness(t)
		_, raw, _ := h.auth.CreateRegistrationToken(ctx, theauth.CreateRegistrationTokenInput{
			Scopes: []string{"files.read"}, GrantTypes: []string{"client_credentials"},
		})
		for _, body := range []string{
			`{"grant_types":["client_credentials"],"scope":"files.write"}`,
			`{"grant_types":["client_credentials","refresh_token"],"scope":"files.read"}`,
		} {
			code, resp := h.registerWith(raw, body)
			if code != http.StatusBadRequest || resp["error"] != "invalid_client_metadata" {
				t.Fatalf("over-scoped %s: %d %v", body, code, resp)
			}
		}
		if code, resp := h.registerWith(raw, agentBody); code != http.StatusCreated {
			t.Fatalf("token should still work after rejected attempts: %d %v", code, resp)
		}
	})

	t.Run("a registration that fails validation gives the use back", func(t *testing.T) {
		h := newDeviceHarness(t)
		_, raw, _ := h.auth.CreateRegistrationToken(ctx, theauth.CreateRegistrationTokenInput{})
		if code, _ := h.registerWith(raw, `{"grant_types":["not-a-grant"]}`); code != http.StatusBadRequest {
			t.Fatalf("invalid metadata status %d", code)
		}
		if code, resp := h.registerWith(raw, agentBody); code != http.StatusCreated {
			t.Fatalf("token was burned by a failed registration: %d %v", code, resp)
		}
	})

	t.Run("revoked and expired tokens are refused", func(t *testing.T) {
		h := newDeviceHarness(t)
		tok, revoked, _ := h.auth.CreateRegistrationToken(ctx, theauth.CreateRegistrationTokenInput{})
		_, expiring, _ := h.auth.CreateRegistrationToken(ctx, theauth.CreateRegistrationTokenInput{TTL: time.Minute})
		if err := h.auth.RevokeRegistrationToken(ctx, tok.ID); err != nil {
			t.Fatal(err)
		}
		if err := h.auth.RevokeRegistrationToken(ctx, tok.ID); err != nil {
			t.Fatalf("revoking twice should succeed: %v", err)
		}
		h.clock.Advance(2 * time.Minute)
		for name, raw := range map[string]string{"revoked": revoked, "expired": expiring} {
			if code, _ := h.registerWith(raw, agentBody); code != http.StatusUnauthorized {
				t.Fatalf("%s token: status %d", name, code)
			}
		}
	})

	t.Run("static operator tokens and anonymous rules are unchanged", func(t *testing.T) {
		h := newDeviceHarness(t)
		if code, _ := h.registerWith("static-token", agentBody); code != http.StatusCreated {
			t.Fatalf("static token: %d", code)
		}
		if code, _ := h.registerWith("rt_made-up", agentBody); code != http.StatusUnauthorized {
			t.Fatalf("made-up token: %d", code)
		}
		if code, _ := h.registerWith("", agentBody); code != http.StatusUnauthorized {
			t.Fatalf("anonymous: %d", code)
		}
	})
}
