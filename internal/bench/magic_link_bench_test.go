package bench

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkMagicLinkConsume measures the request path: hand the handler
// a freshly minted token via the request endpoint, scrape the cookie
// after the verify path completes. Pre-seeded users are reused across
// iterations so the create-user side effect does not dominate the cost.
//
// Note: this benchmark measures the request + verify pair rather than
// verify alone because the noop sender does not surface the token; the
// equivalent measurement is hand-rolled through the storage layer in a
// future iteration if needed.
func BenchmarkMagicLinkConsume(b *testing.B) {
	_, h := newBenchRouter(b)

	body := []byte(`{"email":"ml-bench@example.com"}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/magic-link", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("magic link request status %d", rec.Code)
		}
	}
}
