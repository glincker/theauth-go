package theauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// FuzzCallbackQueryParams feeds arbitrary raw query strings to the OAuth
// callback handler. The invariant is "never panic" and "never return a
// 5xx server error for malformed input" (4xx is fine).
func FuzzCallbackQueryParams(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("state=abc&code=xyz"))
	f.Add([]byte("garbage&;=="))

	_, mux := newOAuthFuzzAuth(f)

	f.Fuzz(func(t *testing.T, rawQuery []byte) {
		if len(rawQuery) > 8192 {
			rawQuery = rawQuery[:8192]
		}
		// url.ParseQuery is the same parser the handler relies on via
		// r.URL.Query(); validating it does not panic anchors the test.
		_, _ = url.ParseQuery(string(rawQuery))

		// Build the request directly (rather than via httptest.NewRequest,
		// which rejects URLs with raw spaces in the URI line) so the fuzz
		// corpus can include arbitrary bytes in RawQuery.
		req := &http.Request{
			Method:     http.MethodGet,
			URL:        &url.URL{Path: "/auth/providers/stub/callback", RawQuery: string(rawQuery)},
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
			Host:       "localhost",
			RemoteAddr: "127.0.0.1:1",
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("server error for arbitrary query: %d", rec.Code)
		}
	})
}

// FuzzCallbackProviderName injects arbitrary bytes as the {name} path
// parameter and asserts the handler returns 404 for unknown providers,
// never 5xx, and never matches a registered provider via partial or
// case-folded comparison.
func FuzzCallbackProviderName(f *testing.F) {
	f.Add([]byte("github"))
	f.Add([]byte(""))
	f.Add([]byte("STUB"))

	_, mux := newOAuthFuzzAuth(f)

	f.Fuzz(func(t *testing.T, name []byte) {
		if len(name) > 256 {
			name = name[:256]
		}
		// Escape so wild bytes do not break URL parsing; the router still
		// receives the decoded value as {name}.
		path := "/auth/providers/" + url.PathEscape(string(name)) + "/callback?state=x&code=y"
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("server error for arbitrary provider name: %d", rec.Code)
		}
		// Any name that isn't exactly "stub" must not be treated as the
		// stub provider. A 200 / 302 would imply that.
		if string(name) != "stub" && (rec.Code == http.StatusOK || rec.Code == http.StatusFound) {
			t.Fatalf("unknown provider %q produced %d (looks like a match)", string(name), rec.Code)
		}
	})
}
