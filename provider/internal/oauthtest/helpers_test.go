package oauthtest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// fakeTB satisfies enough of testing.TB to capture Errorf / Fatalf calls
// without affecting the surrounding real test run. Helpers in this
// package take testing.TB precisely so they can be exercised against this
// fake.
type fakeTB struct {
	testing.TB
	mu       sync.Mutex
	errors   []string
	failed   bool
	cleanups []func()
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Errorf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errors = append(f.errors, fmt.Sprintf(format, args...))
	f.failed = true
}

func (f *fakeTB) Fatalf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errors = append(f.errors, fmt.Sprintf(format, args...))
	f.failed = true
}

func (f *fakeTB) Cleanup(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleanups = append(f.cleanups, fn)
}

func (f *fakeTB) runCleanups() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.cleanups) - 1; i >= 0; i-- {
		f.cleanups[i]()
	}
	f.cleanups = nil
}

func TestAssertTokenFormCatchesMismatch(t *testing.T) {
	body := url.Values{}
	body.Set("client_id", "wrong")
	body.Set("client_secret", "csec")
	body.Set("code", "abc")
	body.Set("code_verifier", "v")
	body.Set("redirect_uri", "https://r")
	body.Set("grant_type", "authorization_code")
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ft := &fakeTB{}
	AssertTokenForm(ft, req, TokenExpect{
		ClientID:     "right", // mismatch on purpose
		ClientSecret: "csec",
		Code:         "abc",
		CodeVerifier: "v",
		RedirectURI:  "https://r",
		GrantType:    "authorization_code",
	})
	if !ft.failed {
		t.Fatal("expected AssertTokenForm to record a failure on client_id mismatch")
	}
	if len(ft.errors) != 1 {
		t.Fatalf("expected exactly one recorded error, got %d: %v", len(ft.errors), ft.errors)
	}
	if !strings.Contains(ft.errors[0], "client_id") {
		t.Fatalf("error %q does not mention the offending field", ft.errors[0])
	}
}

func TestAssertTokenFormSkipsEmptyExpectations(t *testing.T) {
	body := url.Values{}
	body.Set("client_id", "anything")
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ft := &fakeTB{}
	AssertTokenForm(ft, req, TokenExpect{})
	if ft.failed {
		t.Fatalf("expected no failures on empty expectations, got: %v", ft.errors)
	}
}

func TestAssertBearerCatchesMismatch(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer wrong")

	ft := &fakeTB{}
	AssertBearer(ft, req, "right")
	if !ft.failed {
		t.Fatal("expected AssertBearer to record a failure on token mismatch")
	}
}

func TestWriteJSONSetsContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(t, rec, map[string]string{"hello": "world"})
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}
	var decoded map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded["hello"] != "world" {
		t.Fatalf("payload = %+v, want hello=world", decoded)
	}
}

func TestNewMuxRegistersCleanup(t *testing.T) {
	ft := &fakeTB{}
	mux, srv := NewMux(ft)
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pong"))
	})
	resp, err := http.Get(srv.URL + "/ping")
	if err != nil {
		t.Fatalf("GET pre-cleanup: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "pong" {
		t.Fatalf("body = %q, want pong", string(body))
	}

	// Run the cleanups the fake recorded. After this the server must be
	// closed; further requests should fail.
	ft.runCleanups()
	resp, err = http.Get(srv.URL + "/ping")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected error connecting to closed httptest server after cleanup ran")
	}
}
