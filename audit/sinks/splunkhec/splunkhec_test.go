package splunkhec_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/audit/sinks/splunkhec"
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

func TestSplunkHECSinkAuth(t *testing.T) {
	t.Parallel()

	const wantToken = "test-hec-token-abc"
	var gotAuth string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	sink, err := splunkhec.New(srv.URL, wantToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	batch := []models.AuditEvent{makeEvent("user.login"), makeEvent("user.logout")}
	if err := sink.Stream(context.Background(), batch); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Auth header must be "Splunk <token>".
	if got, want := gotAuth, "Splunk "+wantToken; got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}

	// Body must be newline-delimited HEC envelopes; each must have "event",
	// "source", and "sourcetype" fields.
	lines := strings.Split(strings.TrimSpace(string(gotBody)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 HEC events, got %d (body=%q)", len(lines), gotBody)
	}
	for i, line := range lines {
		var env map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatalf("line %d: json decode: %v", i, err)
		}
		if _, ok := env["event"]; !ok {
			t.Errorf("line %d: missing 'event' key", i)
		}
		if _, ok := env["source"]; !ok {
			t.Errorf("line %d: missing 'source' key", i)
		}
		if _, ok := env["sourcetype"]; !ok {
			t.Errorf("line %d: missing 'sourcetype' key", i)
		}
		// source must be "theauth-go"
		var src string
		if err := json.Unmarshal(env["source"], &src); err != nil || src != "theauth-go" {
			t.Errorf("line %d: source = %q, want %q", i, src, "theauth-go")
		}
	}
}

func TestSplunkHECSinkFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{"2xx success", http.StatusOK, false},
		{"4xx config error", http.StatusUnauthorized, true},
		{"5xx server error", http.StatusInternalServerError, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer srv.Close()

			sink, err := splunkhec.New(srv.URL, "tok")
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			err = sink.Stream(context.Background(), []models.AuditEvent{makeEvent("test")})
			if tc.wantErr && err == nil {
				t.Errorf("expected error for status %d, got nil", tc.statusCode)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected nil error for status %d, got %v", tc.statusCode, err)
			}
		})
	}
}

func TestSplunkHECSinkRedactorOverride(t *testing.T) {
	t.Parallel()

	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Redactor strips the email field from metadata.
	redactor := func(evt models.AuditEvent) models.AuditEvent {
		delete(evt.Metadata, "email")
		return evt
	}
	sink, err := splunkhec.New(srv.URL, "tok", splunkhec.WithRedactor(redactor))
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
