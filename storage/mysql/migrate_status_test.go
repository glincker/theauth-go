package mysql

import (
	"testing"
	"time"
)

func TestParseLedgerTime(t *testing.T) {
	want := time.Date(2026, 10, 1, 12, 30, 5, 0, time.UTC)
	tests := []struct {
		name string
		in   any
		want time.Time
	}{
		{"time", want, want},
		{"bytes", []byte("2026-10-01 12:30:05.000000"), want},
		{"string seconds", "2026-10-01 12:30:05", want},
		{"garbage", "nope", time.Time{}},
		{"nil", nil, time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseLedgerTime(tt.in); !got.Equal(tt.want) {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}
