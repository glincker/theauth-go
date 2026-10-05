package emailnorm

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		n    Normalizer
		in   string
		want string
	}{
		{"trim and lower", Normalizer{}, "  Foo@Bar.COM\t", "foo@bar.com"},
		{"fullwidth kept without nfkc", Normalizer{}, "ＡＢ@x.com", "ａｂ@x.com"},
		{"fullwidth folded with nfkc", Normalizer{NFKC: true}, " ＡＢ@X.com ", "ab@x.com"},
		{"empty", Normalizer{NFKC: true}, "   ", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.n.Normalize(tc.in); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
