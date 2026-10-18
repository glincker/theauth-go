package hook

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/safehttp"
)

const testSecret = "whsec_test_secret_value"

// vendorServer runs a vendor endpoint built from the exported helpers: verify
// the request, then let respond write the answer.
func vendorServer(t *testing.T, respond func(w http.ResponseWriter, req *GuardRequest, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req, err := VerifyGuardRequest(testSecret, r.Header, body, nil)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		respond(w, req, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func answer(v Verdict) func(http.ResponseWriter, *GuardRequest, *http.Request) {
	return func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
		_ = WriteGuardResponse(w, testSecret, req.RequestID, v)
	}
}

// writeSigned writes body signed with secret for requestID at ts.
func writeSigned(w http.ResponseWriter, secret, requestID string, ts int64, body string) {
	for k, vs := range SignGuardResponse(secret, requestID, []byte(body), ts) {
		w.Header()[k] = vs
	}
	_, _ = io.WriteString(w, body)
}

func newTestGuard(t *testing.T, url string, mod ...func(*HTTPGuardConfig)) *HTTPGuard {
	t.Helper()
	cfg := HTTPGuardConfig{Name: "test-guard", URL: url, Secret: testSecret, AllowLoopback: true}
	for _, m := range mod {
		m(&cfg)
	}
	g, err := NewHTTPGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

var testInput = Input{
	AgentID: "agent_1", Action: "read", Resource: "mcp:github:issues",
	Arguments: map[string]any{"q": "bugs", "token": "user-data"},
	Agent:     AgentInfo{ID: "agent_1", OwnerID: "u1", Name: "bot"},
}

func TestNewHTTPGuardConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  HTTPGuardConfig
		ok   bool
	}{
		{"https", HTTPGuardConfig{Name: "g", URL: "https://guard.example.com/check", Secret: "s"}, true},
		{"http loopback with option", HTTPGuardConfig{Name: "g", URL: "http://127.0.0.1:9/x", Secret: "s", AllowLoopback: true}, true},
		{"http localhost with option", HTTPGuardConfig{Name: "g", URL: "http://localhost:9/x", Secret: "s", AllowLoopback: true}, true},
		{"http ipv6 loopback with option", HTTPGuardConfig{Name: "g", URL: "http://[::1]:9/x", Secret: "s", AllowLoopback: true}, true},
		{"no name", HTTPGuardConfig{URL: "https://guard.example.com", Secret: "s"}, false},
		{"no secret", HTTPGuardConfig{Name: "g", URL: "https://guard.example.com"}, false},
		{"http public host", HTTPGuardConfig{Name: "g", URL: "http://guard.example.com", Secret: "s", AllowLoopback: true}, false},
		{"http loopback without option", HTTPGuardConfig{Name: "g", URL: "http://127.0.0.1:9", Secret: "s"}, false},
		{"http private ip", HTTPGuardConfig{Name: "g", URL: "http://10.0.0.1", Secret: "s", AllowLoopback: true}, false},
		{"credentials", HTTPGuardConfig{Name: "g", URL: "https://user:pw@guard.example.com", Secret: "s"}, false},
		{"relative", HTTPGuardConfig{Name: "g", URL: "/check", Secret: "s"}, false},
		{"other scheme", HTTPGuardConfig{Name: "g", URL: "ftp://guard.example.com", Secret: "s"}, false},
		{"garbage", HTTPGuardConfig{Name: "g", URL: "https://%zz", Secret: "s"}, false},
		{"protocol header", HTTPGuardConfig{Name: "g", URL: "https://guard.example.com", Secret: "s", Headers: map[string]string{"x-theauth-signature": "v1=x"}}, false},
		{"extra header", HTTPGuardConfig{Name: "g", URL: "https://guard.example.com", Secret: "s", Headers: map[string]string{"X-Api-Key": "k"}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewHTTPGuard(tc.cfg)
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want ok=%v", err, tc.ok)
			}
			if err != nil && strings.Contains(err.Error(), "pw@") {
				t.Fatalf("error leaks the URL: %v", err)
			}
		})
	}
}

func TestHTTPGuardRoundTrip(t *testing.T) {
	var mu sync.Mutex
	var seenHeader http.Header
	var seenInput Input
	decide := Verdict{}
	srv := vendorServer(t, func(w http.ResponseWriter, req *GuardRequest, r *http.Request) {
		mu.Lock()
		seenHeader, seenInput = r.Header.Clone(), req.Input
		v := decide
		mu.Unlock()
		_ = WriteGuardResponse(w, testSecret, req.RequestID, v)
	})
	g := newTestGuard(t, srv.URL+"/theauth", func(c *HTTPGuardConfig) {
		c.KeyID = "prod-1"
		c.Headers = map[string]string{"X-Vendor-Key": "vk"}
	})
	tests := []struct {
		name     string
		verdict  Verdict
		wantDec  Decision
		wantCode Code
		wantRule string
		wantGd   string
	}{
		{"allow", Verdict{Decision: Allow}, Allow, "", "", ""},
		{"deny with code", Verdict{Decision: Deny, Reason: "blocked by rule 7", Code: "R7"}, Deny, CodeHookDenied, "R7", "test-guard"},
		{"deny with vendor guard name", Verdict{Decision: Deny, Reason: "no", Guard: "hol-guard"}, Deny, CodeHookDenied, "", "hol-guard"},
		{"escalate", Verdict{Decision: Escalate, Reason: "needs a human"}, Escalate, CodeApprovalRequired, "", "test-guard"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			decide = tc.verdict
			mu.Unlock()
			out := (&Runner{Hook: g, Timeout: 2 * time.Second}).Run(context.Background(), testInput)
			if out.Decision != tc.wantDec || out.Code != tc.wantCode || out.RuleID != tc.wantRule || out.Guard != tc.wantGd {
				t.Fatalf("got %+v", out)
			}
			mu.Lock()
			defer mu.Unlock()
			if seenHeader.Get(HeaderVersion) != ProtocolVersion || seenHeader.Get(HeaderKeyID) != "prod-1" ||
				seenHeader.Get("X-Vendor-Key") != "vk" || seenHeader.Get("Content-Type") != "application/json" {
				t.Fatalf("headers %v", seenHeader)
			}
			if seenInput.Resource != "mcp:github:issues" || seenInput.Agent.OwnerID != "u1" ||
				seenInput.Arguments["q"] != "bugs" || len(seenInput.Delegation.Path) != 1 || seenInput.Source != SourceAuthorize {
				t.Fatalf("vendor saw %+v", seenInput)
			}
		})
	}
}

func TestHTTPGuardRedact(t *testing.T) {
	var got Input
	srv := vendorServer(t, func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
		got = req.Input
		_ = WriteGuardResponse(w, testSecret, req.RequestID, Verdict{Decision: Allow})
	})
	g := newTestGuard(t, srv.URL, func(c *HTTPGuardConfig) {
		c.Redact = func(in Input) Input { in.Arguments = nil; return in }
	})
	if _, err := g.BeforeAuthorize(context.Background(), testInput); err != nil {
		t.Fatal(err)
	}
	if got.Arguments != nil {
		t.Fatalf("arguments left the process: %v", got.Arguments)
	}
}

// Every bad response fails closed with hook_error.
func TestHTTPGuardRefusesBadResponses(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("redirect was followed")
	}))
	t.Cleanup(other.Close)
	big := `{"decision":"allow","reason":"` + strings.Repeat("a", MaxBodyBytes) + `"}`
	tests := []struct {
		name    string
		respond func(w http.ResponseWriter, req *GuardRequest, r *http.Request)
		want    string
	}{
		{"tampered body", func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
			for k, vs := range SignGuardResponse(testSecret, req.RequestID, []byte(`{"decision":"deny","reason":"no"}`), 0) {
				w.Header()[k] = vs
			}
			_, _ = io.WriteString(w, `{"decision":"allow"}`)
		}, "bad response signature"},
		{"wrong secret", func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
			writeSigned(w, "attacker", req.RequestID, time.Now().Unix(), `{"decision":"allow"}`)
		}, "bad response signature"},
		{"unsigned", func(w http.ResponseWriter, _ *GuardRequest, _ *http.Request) {
			_, _ = io.WriteString(w, `{"decision":"allow"}`)
		}, "missing response signature"},
		{"stale response", func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
			writeSigned(w, testSecret, req.RequestID, time.Now().Unix()-301, `{"decision":"allow"}`)
		}, "stale response"},
		{"future response", func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
			writeSigned(w, testSecret, req.RequestID, time.Now().Unix()+301, `{"decision":"allow"}`)
		}, "stale response"},
		{"bad response timestamp", func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
			w.Header().Set(HeaderResponseTimestamp, "soon")
			w.Header().Set(HeaderResponseSignature, "v1=00")
			_, _ = io.WriteString(w, `{"decision":"allow"}`)
		}, "bad response timestamp"},
		{"signed for another request", func(w http.ResponseWriter, _ *GuardRequest, _ *http.Request) {
			writeSigned(w, testSecret, "some-other-request", time.Now().Unix(), `{"decision":"allow"}`)
		}, "bad response signature"},
		{"server error", func(w http.ResponseWriter, _ *GuardRequest, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, "answered HTTP 500"},
		{"redirect", func(w http.ResponseWriter, _ *GuardRequest, r *http.Request) {
			http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
		}, "redirect, refused"},
		{"oversize with length", func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
			writeSigned(w, testSecret, req.RequestID, time.Now().Unix(), big)
		}, "too large"},
		{"oversize chunked", func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
			for k, vs := range SignGuardResponse(testSecret, req.RequestID, []byte(big), 0) {
				w.Header()[k] = vs
			}
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, big)
		}, "too large"},
		{"unknown field", func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
			writeSigned(w, testSecret, req.RequestID, time.Now().Unix(), `{"decision":"allow","override":true}`)
		}, "unknown field"},
		{"not json", func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
			writeSigned(w, testSecret, req.RequestID, time.Now().Unix(), `allow`)
		}, "malformed verdict"},
		{"deny without reason", func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
			writeSigned(w, testSecret, req.RequestID, time.Now().Unix(), `{"decision":"deny"}`)
		}, "non-empty reason"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := vendorServer(t, tc.respond)
			g := newTestGuard(t, srv.URL)
			_, err := g.BeforeAuthorize(context.Background(), testInput)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), srv.URL) || strings.Contains(err.Error(), testSecret) {
				t.Fatalf("error must name the origin and never the secret: %v", err)
			}
			out := (&Runner{Hook: g}).Run(context.Background(), testInput)
			if out.Decision != Deny || out.Code != CodeHookError {
				t.Fatalf("runner outcome %s/%s, want deny/hook_error", out.Decision, out.Code)
			}
		})
	}
}

// A signed allow captured from one call does not verify for the next one,
// because the signature binds the response to the fresh request id.
func TestHTTPGuardRefusesReplayedResponse(t *testing.T) {
	var mu sync.Mutex
	var captured struct {
		header http.Header
		body   string
	}
	srv := vendorServer(t, func(w http.ResponseWriter, req *GuardRequest, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if captured.header == nil {
			rec := httptest.NewRecorder()
			_ = WriteGuardResponse(rec, testSecret, req.RequestID, Verdict{Decision: Allow})
			captured.header, captured.body = rec.Header(), rec.Body.String()
		}
		for k, vs := range captured.header {
			w.Header()[k] = vs
		}
		_, _ = io.WriteString(w, captured.body)
	})
	g := newTestGuard(t, srv.URL)
	if _, err := g.BeforeAuthorize(context.Background(), testInput); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, err := g.BeforeAuthorize(context.Background(), testInput); err == nil || !strings.Contains(err.Error(), "bad response signature") {
		t.Fatalf("replayed response accepted: %v", err)
	}
}

func TestHTTPGuardBlocksNonPublicAddresses(t *testing.T) {
	loop := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("blocked address was reached")
	}))
	t.Cleanup(loop.Close)
	port := loop.Listener.Addr().String()[strings.LastIndex(loop.Listener.Addr().String(), ":")+1:]
	for _, u := range []string{
		"https://10.0.0.1/check",
		"https://192.168.1.1/check",
		"https://169.254.169.254/latest/meta-data",
		"https://100.64.0.1/check",
		"https://127.0.0.1:" + port + "/check",
		"https://localhost:" + port + "/check",
	} {
		t.Run(u, func(t *testing.T) {
			g, err := NewHTTPGuard(HTTPGuardConfig{Name: "g", URL: u, Secret: testSecret})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err = g.BeforeAuthorize(ctx, testInput)
			if !errors.Is(err, safehttp.ErrBlockedAddress) {
				t.Fatalf("got %v, want ErrBlockedAddress", err)
			}
		})
	}
}

// AllowLoopback opens loopback only: a TLS stub on 127.0.0.1 works with it.
func TestHTTPGuardTLSLoopback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := VerifyGuardRequest(testSecret, r.Header, body, nil)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = WriteGuardResponse(w, testSecret, req.RequestID, Verdict{Decision: Allow})
	}))
	t.Cleanup(srv.Close)
	g := newTestGuard(t, srv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	g.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	v, err := g.BeforeAuthorize(context.Background(), testInput)
	if err != nil || v.Decision != Allow {
		t.Fatalf("got %+v, %v", v, err)
	}
}

func TestHTTPGuardErrorsNameOriginOnly(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	origin := srv.URL
	srv.Close() // connection refused from here on
	g := newTestGuard(t, origin+"/hidden/path?token=abc123", func(c *HTTPGuardConfig) {
		c.Headers = map[string]string{"X-Api-Key": "vendor-api-key"}
		c.ResponseSecret = "response-secret-value"
	})
	_, err := g.BeforeAuthorize(context.Background(), testInput)
	if err == nil {
		t.Fatal("want an error")
	}
	msg := err.Error()
	for _, leak := range []string{"hidden", "token=abc123", testSecret, "vendor-api-key", "response-secret-value", "user-data"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error leaks %q: %s", leak, msg)
		}
	}
	if !strings.Contains(msg, origin) {
		t.Fatalf("error must name the origin: %s", msg)
	}
	for _, s := range []string{g.String(), fmt.Sprintf("%v", g), fmt.Sprintf("%+v", g), fmt.Sprintf("%#v", g)} {
		if strings.Contains(s, testSecret) || strings.Contains(s, "hidden") {
			t.Fatalf("formatting leaks: %s", s)
		}
	}
}

func TestHTTPGuardTimeout(t *testing.T) {
	srv := vendorServer(t, func(w http.ResponseWriter, req *GuardRequest, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	g := newTestGuard(t, srv.URL)
	start := time.Now()
	out := (&Runner{Hook: g, Timeout: 50 * time.Millisecond}).Run(context.Background(), testInput)
	if out.Decision != Deny || out.Code != CodeHookTimeout {
		t.Fatalf("got %s/%s (cause %v), want deny/hook_timeout", out.Decision, out.Code, out.Cause)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not enforced")
	}
	requireNoLeak(t)
}

// A vendor that checks the timestamp refuses a request whose clock is off.
func TestHTTPGuardClockSkewRefusedByVendor(t *testing.T) {
	srv := vendorServer(t, answer(Verdict{Decision: Allow}))
	g := newTestGuard(t, srv.URL, func(c *HTTPGuardConfig) {
		c.Now = func() time.Time { return time.Now().Add(-10 * time.Minute) }
	})
	_, err := g.BeforeAuthorize(context.Background(), testInput)
	if err == nil || !strings.Contains(err.Error(), "HTTP "+strconv.Itoa(http.StatusUnauthorized)) {
		t.Fatalf("got %v, want HTTP 401", err)
	}
}
