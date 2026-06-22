package webhook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/audit/sinks/webhook"
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
)

func makeEvent(action string) models.AuditEvent {
	return models.AuditEvent{
		ID:        ulid.New(),
		Action:    action,
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
		Metadata: map[string]any{
			"email": "user@example.com",
		},
	}
}

func TestWebhookSinkHMAC(t *testing.T) {
	t.Parallel()

	secret := []byte("super-secret-key")

	type capturedReq struct {
		sigHeader string
		body      []byte
	}
	var captured []capturedReq

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured = append(captured, capturedReq{
			sigHeader: r.Header.Get("X-CloudEvents-Signature"),
			body:      body,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := webhook.New(srv.URL, secret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	batch := []models.AuditEvent{makeEvent("user.login"), makeEvent("user.signup")}
	if err := sink.Stream(context.Background(), batch); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	if len(captured) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(captured))
	}

	for i, req := range captured {
		sig := req.sigHeader
		if !strings.HasPrefix(sig, "sha256=") {
			t.Errorf("req %d: signature header = %q, want prefix sha256=", i, sig)
			continue
		}
		gotHex := strings.TrimPrefix(sig, "sha256=")
		gotBytes, err := hex.DecodeString(gotHex)
		if err != nil {
			t.Errorf("req %d: bad hex in signature: %v", i, err)
			continue
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(req.body)
		wantBytes := mac.Sum(nil)
		if !hmac.Equal(gotBytes, wantBytes) {
			t.Errorf("req %d: HMAC mismatch: got %x, want %x", i, gotBytes, wantBytes)
		}
	}
}

func TestWebhookSinkCloudEventsShape(t *testing.T) {
	t.Parallel()

	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := webhook.New(srv.URL, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	evt := makeEvent("user.login")
	if err := sink.Stream(context.Background(), []models.AuditEvent{evt}); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	var ce map[string]json.RawMessage
	if err := json.Unmarshal(capturedBody, &ce); err != nil {
		t.Fatalf("decode CloudEvent: %v", err)
	}
	for _, field := range []string{"specversion", "type", "source", "id", "time", "datacontenttype", "data"} {
		if _, ok := ce[field]; !ok {
			t.Errorf("CloudEvent missing field %q", field)
		}
	}

	var specver string
	if err := json.Unmarshal(ce["specversion"], &specver); err != nil || specver != "1.0" {
		t.Errorf("specversion = %q, want %q", specver, "1.0")
	}
	var ceType string
	if err := json.Unmarshal(ce["type"], &ceType); err == nil {
		if !strings.HasPrefix(ceType, "com.theauth.audit.v1.") {
			t.Errorf("type = %q, want prefix com.theauth.audit.v1.", ceType)
		}
	}
}

func TestWebhookSinkStatusFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{"2xx success", http.StatusNoContent, false},
		{"4xx", http.StatusBadRequest, true},
		{"5xx", http.StatusServiceUnavailable, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer srv.Close()

			sink, err := webhook.New(srv.URL, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			err = sink.Stream(context.Background(), []models.AuditEvent{makeEvent("test")})
			if tc.wantErr && err == nil {
				t.Errorf("expected error for status %d", tc.statusCode)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for status %d: %v", tc.statusCode, err)
			}
		})
	}
}

func TestWebhookSinkRedactorOverride(t *testing.T) {
	t.Parallel()

	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	redactor := func(evt models.AuditEvent) models.AuditEvent {
		delete(evt.Metadata, "email")
		return evt
	}
	sink, err := webhook.New(srv.URL, nil, webhook.WithRedactor(redactor))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	evt := makeEvent("user.login")
	evt.Metadata["email"] = "sensitive@example.com"
	if err := sink.Stream(context.Background(), []models.AuditEvent{evt}); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	if strings.Contains(string(capturedBody), "sensitive@example.com") {
		t.Errorf("email still present in outbound body after redactor override")
	}
}
