package webhook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/audit/sinks/webhook"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
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
		tsHeader  string
		body      []byte
	}
	var captured []capturedReq

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured = append(captured, capturedReq{
			sigHeader: r.Header.Get("X-CloudEvents-Signature"),
			tsHeader:  r.Header.Get("X-CloudEvents-Timestamp"),
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
		if !strings.HasPrefix(req.sigHeader, "sha256=") {
			t.Errorf("req %d: signature header = %q, want prefix sha256=", i, req.sigHeader)
			continue
		}
		if err := webhook.Verify(secret, req.body, req.sigHeader, req.tsHeader, 0, time.Now()); err != nil {
			t.Errorf("req %d: Verify: %v", i, err)
		}
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()
	secret := []byte("k")
	body := []byte(`{"a":1}`)
	now := time.Unix(1_800_000_000, 0)
	signAt := func(ts int64, sec, b []byte) (string, string) {
		tss := strconv.FormatInt(ts, 10)
		mac := hmac.New(sha256.New, sec)
		mac.Write([]byte(tss + "."))
		mac.Write(b)
		return "sha256=" + hex.EncodeToString(mac.Sum(nil)), tss
	}
	fresh, freshTS := signAt(now.Unix(), secret, body)
	old, oldTS := signAt(now.Add(-10*time.Minute).Unix(), secret, body)
	future, futureTS := signAt(now.Add(10*time.Minute).Unix(), secret, body)
	other, otherTS := signAt(now.Unix(), []byte("x"), body)
	bodyOnly := hmac.New(sha256.New, secret)
	bodyOnly.Write(body)
	tests := []struct {
		name      string
		body      []byte
		sig, ts   string
		wantErrIs error
	}{
		{"fresh ok", body, fresh, freshTS, nil},
		{"stale rejected", body, old, oldTS, webhook.ErrTimestampStale},
		{"future rejected", body, future, futureTS, webhook.ErrTimestampStale},
		{"wrong secret", body, other, otherTS, webhook.ErrSignatureMismatch},
		{"tampered body", []byte(`{"a":2}`), fresh, freshTS, webhook.ErrSignatureMismatch},
		{"timestamp swapped", body, fresh, oldTS, webhook.ErrSignatureMismatch},
		{"legacy body-only mac", body, "sha256=" + hex.EncodeToString(bodyOnly.Sum(nil)), freshTS, webhook.ErrSignatureMismatch},
		{"missing headers", body, "", "", webhook.ErrSignatureMissing},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := webhook.Verify(secret, tc.body, tc.sig, tc.ts, 0, now)
			if !errors.Is(err, tc.wantErrIs) {
				t.Fatalf("got %v want %v", err, tc.wantErrIs)
			}
		})
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
