package apitokens

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func FuzzBearerToken(f *testing.F) {
	for _, s := range []string{"", "Bearer", "Bearer ", "Bearer  ", "bearer abc", "BEARER abc", "Basic abc", "Bearer a\x00b", "Bearer " + strings.Repeat("x", 1<<16), "Béarer abc", "Bearer\tabc"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header["Authorization"] = []string{header}
		tok, ok := BearerToken(r)
		if !ok {
			return
		}
		if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
			t.Fatalf("accepted non-bearer header %q", header)
		}
		if tok != strings.TrimSpace(tok) {
			t.Fatalf("token not trimmed: %q", tok)
		}
	})
}
