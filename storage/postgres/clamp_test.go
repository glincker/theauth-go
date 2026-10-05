package postgres

import (
	"math"
	"testing"
)

func TestClampInt32(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int32
	}{
		{"negative", -5, 0},
		{"zero", 0, 0},
		{"in range", 200, 200},
		{"max int32", math.MaxInt32, math.MaxInt32},
		{"above int32", math.MaxInt32 + 1, math.MaxInt32},
		{"huge", math.MaxInt64, math.MaxInt32},
		{"very negative", math.MinInt64, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampInt32(tc.in); got != tc.want {
				t.Fatalf("clampInt32(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
