package cimd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestResolveSingleFlight(t *testing.T) {
	t.Parallel()
	inHandler := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var ts *testServer
	ts = newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(inHandler) })
		<-release
		serveDoc(Document{ClientID: ts.URL(), RedirectURIs: []string{"https://example.org/cb"}})(w, r)
	})
	svc := NewService(Config{TrustPolicy: AllowAnyHTTPS(), HTTPClient: trustingClient(5 * time.Second)}, nil)

	const callers = 8
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() {
			_, err := svc.Resolve(context.Background(), ts.URL())
			errs <- err
		}()
	}
	<-inHandler
	close(release)
	for i := 0; i < callers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("resolve: %v", err)
		}
	}
	if got := ts.hits.Load(); got != 1 {
		t.Fatalf("expected 1 upstream hit for %d concurrent callers, got %d", callers, got)
	}
}

func TestResolveNegativeCache(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		negTTL     time.Duration
		wantHits   int64
		handler    http.HandlerFunc
		wantErrIs  error
		callsCount int
	}{
		{"failure cached", time.Minute, 1, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, ErrFetchFailed, 3},
		{"cache disabled with negative ttl", -1, 3, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, ErrFetchFailed, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t, tc.handler)
			svc := NewService(Config{
				TrustPolicy: AllowAnyHTTPS(), NegativeCacheTTL: tc.negTTL,
				HTTPClient: trustingClient(2 * time.Second),
			}, nil)
			for i := 0; i < tc.callsCount; i++ {
				if _, err := svc.Resolve(context.Background(), ts.URL()); !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("call %d: want %v, got %v", i, tc.wantErrIs, err)
				}
			}
			if got := ts.hits.Load(); got != tc.wantHits {
				t.Fatalf("hits=%d want %d", got, tc.wantHits)
			}
		})
	}
}

func TestResolveDefaultBodyCap(t *testing.T) {
	t.Parallel()
	pad := strings.Repeat("a", 6*1024)
	var ts *testServer
	ts = newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"client_id":%q,"redirect_uris":["https://x/cb"],"pad":%q}`, ts.URL(), pad)
	})
	svc := NewService(Config{TrustPolicy: AllowAnyHTTPS(), HTTPClient: trustingClient(2 * time.Second)}, nil)
	if _, err := svc.Resolve(context.Background(), ts.URL()); !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("6 KiB body must exceed the 5 KiB default, got %v", err)
	}
}

func TestValidateRedirectURI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		uri     string
		wantErr bool
	}{
		{"https://app.example.com/cb", false},
		{"http://127.0.0.1:3000/callback", false},
		{"http://[::1]:3000/callback", false},
		{"com.example.app:/cb", false},
		{"javascript:alert(1)", true},
		{"data:text/html,x", true},
		{"file:///etc/passwd", true},
		{"myapp://cb", true},
		{"http://evil.example.com/cb", true},
		{"https://u:p@app.example.com/cb", true},
	}
	for _, tc := range tests {
		if err := ValidateRedirectURI(tc.uri); (err != nil) != tc.wantErr {
			t.Errorf("ValidateRedirectURI(%q) err=%v wantErr=%v", tc.uri, err, tc.wantErr)
		}
	}
}
