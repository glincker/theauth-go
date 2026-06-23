package otlp_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	theauth "github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/audit/sinks/otlp"
	collectorlogsv1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"
)

func makeEvent(action string) theauth.AuditEvent {
	return theauth.AuditEvent{
		Action:    action,
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
		Metadata: map[string]any{
			"email": "user@example.com",
		},
	}
}

func TestOTLPSinkSuccessAndFailure(t *testing.T) {
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

			var receivedBody []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedBody, _ = io.ReadAll(r.Body)
				w.WriteHeader(tc.statusCode)
			}))
			defer srv.Close()

			sink, err := otlp.New(srv.URL)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			batch := []theauth.AuditEvent{makeEvent("user.login"), makeEvent("user.signup")}
			streamErr := sink.Stream(context.Background(), batch)

			if tc.wantErr {
				if streamErr == nil {
					t.Errorf("expected error for status %d, got nil", tc.statusCode)
				}
				return
			}
			if streamErr != nil {
				t.Fatalf("Stream: unexpected error: %v", streamErr)
			}

			// On success verify the body is a valid ExportLogsServiceRequest
			// proto with the expected number of log records.
			var req collectorlogsv1.ExportLogsServiceRequest
			if err := proto.Unmarshal(receivedBody, &req); err != nil {
				t.Fatalf("proto.Unmarshal: %v", err)
			}
			if len(req.ResourceLogs) == 0 {
				t.Fatal("ResourceLogs is empty")
			}
			rl := req.ResourceLogs[0]
			if len(rl.ScopeLogs) == 0 {
				t.Fatal("ScopeLogs is empty")
			}
			gotRecords := rl.ScopeLogs[0].LogRecords
			if len(gotRecords) != len(batch) {
				t.Errorf("expected %d log records, got %d", len(batch), len(gotRecords))
			}
			// Verify service.name resource attribute.
			var foundServiceName bool
			for _, attr := range rl.Resource.GetAttributes() {
				if attr.Key == "service.name" {
					foundServiceName = true
					if v := attr.Value.GetStringValue(); v != "theauth-go" {
						t.Errorf("service.name = %q, want theauth-go", v)
					}
				}
			}
			if !foundServiceName {
				t.Error("resource attribute service.name not found")
			}
		})
	}
}

func TestOTLPSinkRedactorOverride(t *testing.T) {
	t.Parallel()

	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	redactor := func(evt theauth.AuditEvent) theauth.AuditEvent {
		delete(evt.Metadata, "email")
		return evt
	}
	sink, err := otlp.New(srv.URL, otlp.WithRedactor(redactor))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	evt := makeEvent("user.login")
	evt.Metadata["email"] = "sensitive@example.com"
	if err := sink.Stream(context.Background(), []theauth.AuditEvent{evt}); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	if strings.Contains(string(receivedBody), "sensitive@example.com") {
		t.Errorf("email still present in outbound proto body after redactor override")
	}
}
