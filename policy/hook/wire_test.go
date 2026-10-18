package hook

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// guardVector is one case of testdata/guard-vectors.json, produced by the
// TypeScript implementation (sdk/packages/core/src/hooks/http-guard.ts).
// Regenerate from sdk/packages/core with the generator kept outside both repos:
//
//	npx tsx go-vectors/gen.mts > ../../../go/policy/hook/testdata/guard-vectors.json
type guardVector struct {
	Name                    string `json:"name"`
	Secret                  string `json:"secret"`
	Timestamp               int64  `json:"timestamp"`
	Now                     int64  `json:"now"`
	RequestID               string `json:"requestId"`
	RequestBody             string `json:"requestBody"`
	RequestSignature        string `json:"requestSignature"`
	RequestSignSecret       string `json:"requestSignSecret"`
	RequestSignedBody       string `json:"requestSignedBody"`
	VerifyRequestID         string `json:"verifyRequestId"`
	ResponseBody            string `json:"responseBody"`
	ResponseTimestamp       int64  `json:"responseTimestamp"`
	ResponseSignature       string `json:"responseSignature"`
	ResponseSignSecret      string `json:"responseSignSecret"`
	ResponseSignedBody      string `json:"responseSignedBody"`
	ResponseSignedRequestID string `json:"responseSignedRequestId"`
	ExpectRequest           struct {
		OK     bool   `json:"ok"`
		Reason string `json:"reason"`
	} `json:"expectRequest"`
	ExpectResponse struct {
		OK     bool   `json:"ok"`
		Reason string `json:"reason"`
	} `json:"expectResponse"`
}

func loadVectors(t *testing.T) []guardVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/guard-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Protocol string        `json:"protocol"`
		Cases    []guardVector `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.Protocol != ProtocolVersion || len(file.Cases) < 7 {
		t.Fatalf("unexpected vector file: protocol %q, %d cases", file.Protocol, len(file.Cases))
	}
	return file.Cases
}

// TestGuardVectors proves wire compatibility with the TypeScript library: the
// Go signers reproduce every TypeScript signature byte for byte, and the Go
// verifiers accept and refuse exactly the cases the TypeScript verifiers do,
// with the same reason text.
func TestGuardVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			if got := SignGuardBody(v.RequestSignSecret, v.Timestamp, []byte(v.RequestSignedBody)); got != v.RequestSignature {
				t.Fatalf("request signature\n got %s\nwant %s", got, v.RequestSignature)
			}
			if got := SignGuardResponseBody(v.ResponseSignSecret, v.ResponseSignedRequestID, v.ResponseTimestamp, []byte(v.ResponseSignedBody)); got != v.ResponseSignature {
				t.Fatalf("response signature\n got %s\nwant %s", got, v.ResponseSignature)
			}
			h := SignGuardResponse(v.ResponseSignSecret, v.ResponseSignedRequestID, []byte(v.ResponseSignedBody), v.ResponseTimestamp)
			if h.Get(HeaderResponseSignature) != v.ResponseSignature || h.Get(HeaderResponseTimestamp) != strconv.FormatInt(v.ResponseTimestamp, 10) {
				t.Fatalf("SignGuardResponse headers %v", h)
			}

			opts := &VerifyOptions{Now: func() time.Time { return time.Unix(v.Now, 0) }}
			reqHeader := http.Header{}
			reqHeader.Set(HeaderTimestamp, strconv.FormatInt(v.Timestamp, 10))
			reqHeader.Set(HeaderSignature, v.RequestSignature)
			req, err := VerifyGuardRequest(v.Secret, reqHeader, []byte(v.RequestBody), opts)
			if v.ExpectRequest.OK {
				if err != nil {
					t.Fatalf("request: TypeScript accepted, Go refused: %v", err)
				}
				if req.RequestID != v.RequestID || req.Input.AgentID != "agent_1" || req.Input.Agent.OwnerID != "u1" {
					t.Fatalf("request parsed as %+v", req)
				}
			} else if err == nil || err.Error() != v.ExpectRequest.Reason {
				t.Fatalf("request: got %v, want %q", err, v.ExpectRequest.Reason)
			}

			respHeader := http.Header{}
			respHeader.Set(HeaderResponseTimestamp, strconv.FormatInt(v.ResponseTimestamp, 10))
			respHeader.Set(HeaderResponseSignature, v.ResponseSignature)
			err = VerifyGuardResponse(v.Secret, v.VerifyRequestID, respHeader, []byte(v.ResponseBody), opts)
			if v.ExpectResponse.OK {
				if err != nil {
					t.Fatalf("response: TypeScript accepted, Go refused: %v", err)
				}
				if _, err := DecodeVerdict([]byte(v.ResponseBody)); err != nil {
					t.Fatalf("verdict: %v", err)
				}
			} else if err == nil || err.Error() != v.ExpectResponse.Reason {
				t.Fatalf("response: got %v, want %q", err, v.ExpectResponse.Reason)
			}
		})
	}
}

func TestDecodeVerdict(t *testing.T) {
	tests := []struct {
		name string
		body string
		want Decision
		ok   bool
	}{
		{"allow", `{"decision":"allow"}`, Allow, true},
		{"allow with reason", `{"decision":"allow","reason":"ok"}`, Allow, true},
		{"deny with code", `{"decision":"deny","reason":"blocked","code":"R7"}`, Deny, true},
		{"escalate with metadata", `{"decision":"escalate","guard":"g","ruleId":"r","metadata":{"a":"b","n":1.5,"t":false}}`, Escalate, true},
		{"whitespace", " {\n\"decision\" : \"allow\" } \n", Allow, true},
		{"unknown field", `{"decision":"allow","extra":1}`, "", false},
		{"case variant key", `{"Decision":"allow"}`, "", false},
		{"case variant duplicate", `{"decision":"deny","reason":"x","Decision":"allow"}`, "", false},
		{"missing decision", `{"reason":"x"}`, "", false},
		{"bad decision", `{"decision":"ALLOW"}`, "", false},
		{"deny without reason", `{"decision":"deny"}`, "", false},
		{"deny empty reason", `{"decision":"deny","reason":""}`, "", false},
		{"null reason", `{"decision":"allow","reason":null}`, "", false},
		{"number reason", `{"decision":"allow","reason":7}`, "", false},
		{"code on allow", `{"decision":"allow","code":"R7"}`, "", false},
		{"code on escalate", `{"decision":"escalate","code":"R7"}`, "", false},
		{"reason too long", `{"decision":"deny","reason":"` + strings.Repeat("a", 1025) + `"}`, "", false},
		{"reason at limit", `{"decision":"deny","reason":"` + strings.Repeat("a", 1024) + `"}`, Deny, true},
		{"guard too long", `{"decision":"allow","guard":"` + strings.Repeat("a", 129) + `"}`, "", false},
		{"nested metadata", `{"decision":"allow","metadata":{"a":{"b":1}}}`, "", false},
		{"null metadata value", `{"decision":"allow","metadata":{"a":null}}`, "", false},
		{"metadata array", `{"decision":"allow","metadata":["a"]}`, "", false},
		{"too many metadata keys", `{"decision":"allow","metadata":{` + manyKeys(17) + `}}`, "", false},
		{"sixteen metadata keys", `{"decision":"allow","metadata":{` + manyKeys(16) + `}}`, Allow, true},
		{"trailing data", `{"decision":"allow"}{"decision":"deny"}`, "", false},
		{"array", `[{"decision":"allow"}]`, "", false},
		{"null", `null`, "", false},
		{"not json", `allow`, "", false},
		{"oversize", `{"decision":"allow","reason":"` + strings.Repeat("a", MaxBodyBytes) + `"}`, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := DecodeVerdict([]byte(tc.body))
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want ok=%v", err, tc.ok)
			}
			if tc.ok && v.Decision != tc.want {
				t.Fatalf("decision %s, want %s", v.Decision, tc.want)
			}
		})
	}
}

func manyKeys(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = `"k` + strconv.Itoa(i) + `":` + strconv.Itoa(i)
	}
	return strings.Join(parts, ",")
}

func signedHeader(secret string, ts int64, body []byte) http.Header {
	h := http.Header{}
	h.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	h.Set(HeaderSignature, SignGuardBody(secret, ts, body))
	return h
}

func TestVerifyGuardRequest(t *testing.T) {
	const secret = "s3cret"
	now := time.Unix(1792261200, 0)
	body, err := encodeRequest("rid-1", now, Input{AgentID: "a1", Action: "read", Resource: "r"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{"rid-replayed": true}
	tests := []struct {
		name    string
		header  http.Header
		body    []byte
		seen    bool
		wantErr error
	}{
		{name: "valid", header: signedHeader(secret, now.Unix(), body), body: body},
		{name: "missing headers", header: http.Header{}, body: body, wantErr: ErrMissingSignature},
		{name: "bad timestamp", header: func() http.Header {
			h := signedHeader(secret, now.Unix(), body)
			h.Set(HeaderTimestamp, "12a")
			return h
		}(), body: body, wantErr: ErrBadTimestamp},
		{name: "stale", header: signedHeader(secret, now.Unix()-301, body), body: body, wantErr: ErrStaleTimestamp},
		{name: "future", header: signedHeader(secret, now.Unix()+301, body), body: body, wantErr: ErrStaleTimestamp},
		{name: "wrong secret", header: signedHeader("other", now.Unix(), body), body: body, wantErr: ErrBadSignature},
		{name: "tampered", header: signedHeader(secret, now.Unix(), body), body: []byte(strings.Replace(string(body), `"read"`, `"write"`, 1)), wantErr: ErrBadSignature},
		{name: "not json", header: signedHeader(secret, now.Unix(), []byte("nope")), body: []byte("nope"), wantErr: ErrMalformedRequest},
		{name: "no resource", header: signedHeader(secret, now.Unix(), []byte(`{"version":"2026-10","requestId":"x","issuedAt":"t","input":{"action":"a"}}`)), body: []byte(`{"version":"2026-10","requestId":"x","issuedAt":"t","input":{"action":"a"}}`), wantErr: ErrMalformedRequest},
		{name: "case variant key", header: signedHeader(secret, now.Unix(), []byte(`{"version":"2026-10","RequestId":"x","requestId":"y","issuedAt":"t","input":{"action":"a","resource":"r"}}`)), body: []byte(`{"version":"2026-10","RequestId":"x","requestId":"y","issuedAt":"t","input":{"action":"a","resource":"r"}}`), wantErr: ErrMalformedRequest},
		{name: "replayed", header: signedHeader(secret, now.Unix(), []byte(`{"version":"2026-10","requestId":"rid-replayed","issuedAt":"t","input":{"action":"a","resource":"r"},"future":1}`)), body: []byte(`{"version":"2026-10","requestId":"rid-replayed","issuedAt":"t","input":{"action":"a","resource":"r"},"future":1}`), seen: true, wantErr: ErrReplayedRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := &VerifyOptions{Now: func() time.Time { return now }}
			if tc.seen {
				opts.Seen = func(id string) bool { return seen[id] }
			}
			req, err := VerifyGuardRequest(secret, tc.header, tc.body, opts)
			if tc.wantErr == nil {
				if err != nil || req.RequestID != "rid-1" || req.Input.Action != "read" {
					t.Fatalf("got %+v, %v", req, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestEncodeRequestShape(t *testing.T) {
	body, err := encodeRequest("rid", time.Date(2026, 10, 17, 19, 0, 0, 0, time.UTC), Input{AgentID: "a1", Action: "read", Resource: "x<y>&z"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"2026-10","requestId":"rid","issuedAt":"2026-10-17T19:00:00.000Z","input":{"agentId":"a1","action":"read","resource":"x<y>&z","agent":{"id":"a1","ownerId":"","type":"autonomous","name":""},"delegation":{"path":["a1"],"links":[],"inbound":[]},"source":"authorize","dryRun":false}}`
	if string(body) != want {
		t.Fatalf("envelope\n got %s\nwant %s", body, want)
	}
	id, err := newRequestID()
	if err != nil || len(id) != 36 || id[14] != '4' {
		t.Fatalf("request id %q, %v", id, err)
	}
}

func TestWriteGuardResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := WriteGuardResponse(rec, "s", "rid", Verdict{Decision: Deny, Reason: "no <way>", Code: "R1"}); err != nil {
		t.Fatal(err)
	}
	body := rec.Body.Bytes()
	if string(body) != `{"decision":"deny","reason":"no <way>","code":"R1"}` {
		t.Fatalf("body %s", body)
	}
	if err := VerifyGuardResponse("s", "rid", rec.Header(), body, nil); err != nil {
		t.Fatal(err)
	}
	if err := WriteGuardResponse(httptest.NewRecorder(), "s", "rid", Verdict{Decision: Deny}); err == nil {
		t.Fatal("a deny without reason must not be written")
	}
}
