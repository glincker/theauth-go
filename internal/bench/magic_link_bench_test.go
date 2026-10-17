package bench

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkMagicLinkConsume measures the request and verify pair. The noop sender does not surface
// the token, so the verify step is not isolated.
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
