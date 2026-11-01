package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// Digests computed independently with python3 hashlib and hmac, so the Go code is not checked
// against itself.
const (
	wantUnkeyedHello = "daa17c8561efd3eae7df21bf972180fef732e84d9582b7e6afee55495ba891ae"
	wantKeyedHello   = "d8af899860039f4076325d2334cd5bdf17390e28a90a7bd9ed34c78b6005fcd0"
)

func TestInputHasherVectors(t *testing.T) {
	t.Parallel()
	var zero InputHasher
	if got := zero.Hash("hello"); got != wantUnkeyedHello {
		t.Fatalf("unkeyed = %s, want %s (the TypeScript hashInputContent digest)", got, wantUnkeyedHello)
	}
	keyed, err := NewInputHasher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if got := keyed.Hash("hello"); got != wantKeyedHello {
		t.Fatalf("keyed = %s, want %s", got, wantKeyedHello)
	}
	if keyed.Alg() != InputHashHMAC || zero.Alg() != InputHashSHA256 {
		t.Fatalf("alg tags: %q, %q", keyed.Alg(), zero.Alg())
	}
	other, _ := NewInputHasher([]byte("another key, long enough"))
	if other.Hash("hello") == keyed.Hash("hello") {
		t.Fatal("different keys gave the same digest")
	}
}

func TestInputHasherKeyLength(t *testing.T) {
	t.Parallel()
	if _, err := NewInputHasher([]byte("short")); !errors.Is(err, ErrInputKeyTooShort) {
		t.Fatalf("short key err = %v", err)
	}
	if _, err := NewInputHasher(nil); err != nil {
		t.Fatalf("empty key must mean unkeyed: %v", err)
	}
}

func TestBuildInputProvenance(t *testing.T) {
	t.Parallel()
	var h InputHasher
	good := h.Hash("doc body")
	long := strings.Repeat("x", 400)
	rec := BuildInputProvenance(h, []InputSource{
		{Kind: InputRetrievedDocument, ID: "doc_1", Content: "doc body"},
		{Kind: InputRetrievedDocument, ID: "doc_1_again", Content: "doc body"}, // duplicate kind+hash
		{Kind: InputUserMessage, Hash: good},
		{Kind: "bogus", Content: "x"},                   // unknown kind
		{Kind: InputAgent},                              // no content, no hash
		{Kind: InputAgent, Hash: "NOTHEX"},              // bad hash
		{Kind: InputToolOutput, ID: long, Content: "y"}, // id is capped
	})
	if rec == nil {
		t.Fatal("nil record")
	}
	srcs := rec["sources"].([]any)
	keys := rec["keys"].([]any)
	if len(srcs) != 3 || len(keys) != 3 {
		t.Fatalf("sources = %d, keys = %d, want 3 each: %v", len(srcs), len(keys), rec)
	}
	if keys[0] != InputRetrievedDocument+":"+good {
		t.Fatalf("keys[0] = %v", keys[0])
	}
	if id := srcs[2].(map[string]any)["id"].(string); len(id) != maxInputIDLen {
		t.Fatalf("id length = %d", len(id))
	}
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), "doc body") {
		t.Fatal("content leaked into the record")
	}
	if BuildInputProvenance(h, nil) != nil || BuildInputProvenance(h, []InputSource{{Kind: "bogus", Content: "x"}}) != nil {
		t.Fatal("nothing valid must give nil")
	}
}

func TestBuildInputProvenanceCapsSources(t *testing.T) {
	t.Parallel()
	var in []InputSource
	for i := 0; i < 80; i++ {
		in = append(in, InputSource{Kind: InputUserMessage, Content: strings.Repeat("a", i+1)})
	}
	rec := BuildInputProvenance(InputHasher{}, in)
	if n := len(rec["sources"].([]any)); n != maxInputSources {
		t.Fatalf("sources = %d, want %d", n, maxInputSources)
	}
}

func TestProvenanceNeedle(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name string
		f    models.ProvenanceFilter
		want string
		bad  bool
	}{
		{"both", models.ProvenanceFilter{Kind: InputAgent, Hash: hash}, `"agent:` + hash + `"`, false},
		{"hash", models.ProvenanceFilter{Hash: hash}, `:` + hash + `"`, false},
		{"kind", models.ProvenanceFilter{Kind: InputUserMessage}, `"user_message:`, false},
		{"empty", models.ProvenanceFilter{}, "", false},
		{"bad kind", models.ProvenanceFilter{Kind: "x"}, "", true},
		{"upper hash", models.ProvenanceFilter{Hash: strings.ToUpper(hash)}, "", true},
		{"short hash", models.ProvenanceFilter{Hash: "ab"}, "", true},
	} {
		got, err := ProvenanceNeedle(tc.f)
		if tc.bad {
			if !errors.Is(err, models.ErrBadProvenanceFilter) {
				t.Errorf("%s: err = %v", tc.name, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
}

// The needle must match what json.Marshal wrote for a record, which is what every store holds.
func TestNeedleMatchesMarshaledRecord(t *testing.T) {
	t.Parallel()
	var h InputHasher
	rec := BuildInputProvenance(h, []InputSource{{Kind: InputToolOutput, ID: "t1", Content: "out"}})
	raw, _ := MarshalOr(rec, "{}")
	hash := h.Hash("out")
	for _, f := range []models.ProvenanceFilter{{Kind: InputToolOutput}, {Hash: hash}, {Kind: InputToolOutput, Hash: hash}} {
		n, _ := ProvenanceNeedle(f)
		if !MatchesProvenance(raw, n) {
			t.Errorf("filter %+v does not match %s", f, raw)
		}
	}
	n, _ := ProvenanceNeedle(models.ProvenanceFilter{Kind: InputUserMessage, Hash: hash})
	if MatchesProvenance(raw, n) {
		t.Error("wrong kind matched")
	}
}

func TestWithInputsAccumulates(t *testing.T) {
	t.Parallel()
	ctx := WithInputs(context.Background(), InputSource{Kind: InputUserMessage, Content: "a"})
	ctx = WithInputs(ctx, InputSource{Kind: InputAgent, Content: "b"})
	if got := InputsFromContext(ctx); len(got) != 2 {
		t.Fatalf("inputs = %d", len(got))
	}
	if WithInputs(context.Background()) == nil || len(InputsFromContext(context.Background())) != 0 {
		t.Fatal("empty context must carry nothing")
	}
}

func TestMergeInputProvenanceKeepsBase(t *testing.T) {
	t.Parallel()
	base := map[string]any{"labels": map[string]any{"*": []any{"untrusted"}}}
	out := MergeInputProvenance(base, map[string]any{"keys": []any{"k"}})
	if out["labels"] == nil || out["keys"] == nil {
		t.Fatalf("merged = %v", out)
	}
	if _, ok := base["keys"]; ok {
		t.Fatal("base was modified")
	}
}
