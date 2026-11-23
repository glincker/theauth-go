package toolguard

import "testing"

func benchHash(b *testing.B, args any) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := HashApprovalAction("execute", "bank:transfer", args); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHashApprovalSmall is a typical tool call: a few scalar arguments.
func BenchmarkHashApprovalSmall(b *testing.B) {
	benchHash(b, map[string]any{"amount": 10, "to": "alice", "memo": "rent", "urgent": false})
}

// BenchmarkHashApprovalNested adds nesting, floats and reserved keys that are stripped.
func BenchmarkHashApprovalNested(b *testing.B) {
	benchHash(b, map[string]any{
		"amount": 12.5, "currency": "USD", "approvalId": "x", "theauthTrace": "y",
		"to":    map[string]any{"name": "alice", "iban": "DE89370400440532013000", "tags": []any{"a", "b", "c"}},
		"lines": []any{map[string]any{"sku": "A1", "qty": 3, "price": 1.25}, map[string]any{"sku": "B2", "qty": 1, "price": 99}},
	})
}

// BenchmarkHashApprovalNil is the no argument call.
func BenchmarkHashApprovalNil(b *testing.B) { benchHash(b, nil) }
