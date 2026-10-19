package toolguard

import (
	"encoding/json"
	"math"
	"math/rand"
	"strings"
	"testing"
)

// The fast path of HashApprovalAction must agree with the encoding/json reference for every
// argument value, including the ones it declines (then it must decline, not guess).

var weirdStrings = []string{
	"", "a", "plain text", "<script>&amp;</script>", "quote\"back\\slash", "tab\tnl\ncr\rbs\bff\f",
	"\x00\x01\x1f\x7f", "unicode \u00e9 \u4e16\u754c \U0001F600", "sep \u2028 \u2029 end", "\ufffd",
	"bad \xff utf8", "trunc \xe4\xb8", "surrogate \xed\xa0\x80", "a/b:c", strings.Repeat("x", 300),
}

func randString(r *rand.Rand) string {
	if r.Intn(3) == 0 {
		return weirdStrings[r.Intn(len(weirdStrings))]
	}
	b := make([]byte, r.Intn(12))
	for i := range b {
		b[i] = byte(r.Intn(256))
	}
	if r.Intn(2) == 0 {
		return strings.ToValidUTF8(string(b), "?")
	}
	return string(b)
}

func randValue(r *rand.Rand, depth int) any {
	n := 16
	if depth >= 3 {
		n = 11
	}
	switch r.Intn(n) {
	case 0:
		return nil
	case 1:
		return r.Intn(2) == 0
	case 2:
		return randString(r)
	case 3:
		return float64(r.Intn(2000) - 1000)
	case 4:
		return []float64{0, math.Copysign(0, -1), 0.1, 1.5, 1e20, 1e21, 1e-6, 1e-7, 123456789.125, math.MaxFloat64, math.SmallestNonzeroFloat64, math.NaN(), math.Inf(1)}[r.Intn(13)]
	case 5:
		return r.Int63() - r.Int63()
	case 6:
		return []int{0, -1, 7, math.MaxInt32}[r.Intn(4)]
	case 7:
		return uint64(r.Int63()) << 1
	case 8:
		return json.Number([]string{"0", "-0", "1", "-12", "1.0", "1e2", "1E+2", "0.5", "10e-1", "9007199254740993", "-0.0", "007", "1e999", "abc", ""}[r.Intn(15)])
	case 9:
		return int8(r.Intn(256) - 128)
	case 10:
		return uint16(r.Intn(65536))
	case 11:
		out := make([]any, r.Intn(4))
		for i := range out {
			out[i] = randValue(r, depth+1)
		}
		if r.Intn(8) == 0 {
			return []any(nil)
		}
		return out
	case 12:
		m := map[string]any{}
		for i, k := 0, r.Intn(5); i < k; i++ {
			m[randString(r)] = randValue(r, depth+1)
		}
		if r.Intn(8) == 0 {
			return map[string]any(nil)
		}
		return m
	case 13:
		out := make([]string, r.Intn(4))
		for i := range out {
			out[i] = randString(r)
		}
		return out
	case 14:
		m := map[string]string{}
		for i, k := 0, r.Intn(4); i < k; i++ {
			m[randString(r)] = randString(r)
		}
		return m
	default:
		// A shape the fast path must decline.
		type pair struct {
			A int    `json:"a"`
			B string `json:"b,omitempty"`
		}
		return []any{pair{1, "x"}, &pair{2, ""}, map[int]string{1: "a"}}[r.Intn(3)]
	}
}

func TestFastApprovalHashEqualsReference(t *testing.T) {
	r := rand.New(rand.NewSource(20261018))
	reserved := []string{"approvalId", "inputProvenance", "theauthTrace", "THEAUTH_x", "TheAuth"}
	fast := 0
	for i := 0; i < 20000; i++ {
		var args any
		switch r.Intn(10) {
		case 0:
			args = nil
		case 1:
			args = map[string]any(nil)
		case 2:
			args = randValue(r, 0)
		default:
			m := map[string]any{}
			for j, k := 0, r.Intn(7); j < k; j++ {
				m[randString(r)] = randValue(r, 1)
			}
			if r.Intn(3) == 0 {
				m[reserved[r.Intn(len(reserved))]] = randValue(r, 1)
			}
			args = m
		}
		action, resource := randString(r), randString(r)
		want, werr := hashApprovalSlow(action, resource, args)
		got, gerr := HashApprovalAction(action, resource, args)
		if (werr != nil) != (gerr != nil) || got != want {
			t.Fatalf("case %d: args %#v action %q resource %q\nfast  %q %v\nslow  %q %v", i, args, action, resource, got, gerr, want, werr)
		}
		if _, ok := fastHashApproval(action, resource, args); ok {
			fast++
		}
	}
	if fast < 5000 {
		t.Fatalf("only %d cases took the fast path, the corpus no longer exercises it", fast)
	}
	t.Logf("%d of 20000 cases took the fast path", fast)
}

func TestFastApprovalHashDeclinesUnknownShapes(t *testing.T) {
	type s struct{ A int }
	for _, a := range []any{s{1}, &s{1}, []any{1}, "str", 5, map[int]int{1: 1}, map[string]any{"k": s{1}}, map[string]any{"k": json.Number("1.5")}, map[string]any{"k": math.NaN()}, map[string]any{"bad\xff": 1}} {
		if _, ok := fastHashApproval("a", "r", a); ok {
			t.Errorf("fast path accepted %#v", a)
		}
	}
}
