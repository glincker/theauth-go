package checkpoint

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"
)

// tsFixture mirrors testdata/ts-fixture.json, written by the TypeScript SDK.
type tsFixture struct {
	HMACKey     string      `json:"hmacKey"`
	Now1        int64       `json:"now1"`
	Now2        int64       `json:"now2"`
	PublicKeys  []PublicKey `json:"publicKeys"`
	PrivateKeys map[string]struct {
		D string `json:"d"`
	} `json:"privateKeys"`
	Rows []struct {
		ID          string         `json:"id"`
		Hash        string         `json:"hash"`
		HashVersion int            `json:"hashVersion"`
		TimestampMs int64          `json:"timestampMs"`
		Fields      map[string]any `json:"fields"`
	} `json:"rows"`
	Checkpoints map[string]Checkpoint `json:"checkpoints"`
	Inclusion   []struct {
		Proof      InclusionProof `json:"proof"`
		Checkpoint Checkpoint     `json:"checkpoint"`
		Expected   expectedOut    `json:"expected"`
	} `json:"inclusion"`
	Consistency struct {
		Proof    ConsistencyProof `json:"proof"`
		Older    Checkpoint       `json:"older"`
		Newer    Checkpoint       `json:"newer"`
		Expected expectedOut      `json:"expected"`
	} `json:"consistency"`
	Receipts []struct {
		Name     string          `json:"name"`
		Receipt  json.RawMessage `json:"receipt"`
		Expected expectedOut     `json:"expected"`
	} `json:"receipts"`
	Negative []struct {
		Name       string          `json:"name"`
		Kind       string          `json:"kind"`
		Checkpoint Checkpoint      `json:"checkpoint"`
		Proof      json.RawMessage `json:"proof"`
		Older      Checkpoint      `json:"older"`
		Newer      Checkpoint      `json:"newer"`
		Receipt    json.RawMessage `json:"receipt"`
		Keys       []PublicKey     `json:"keys"`
		Expected   expectedOut     `json:"expected"`
	} `json:"negative"`
}

type expectedOut struct {
	Valid  bool   `json:"valid"`
	Reason Reason `json:"reason"`
}

func (e expectedOut) outcome() Outcome { return Outcome(e) }

func loadTS(t *testing.T) tsFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/ts-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var f tsFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func signerFromD(t *testing.T, d, keyID string) *Ed25519Signer {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewEd25519Signer(ed25519.NewKeyFromSeed(seed), keyID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f tsFixture) log() Log {
	rows := make(StaticSource, len(f.Rows))
	for i, r := range f.Rows {
		rows[i] = Row{ID: r.ID, Hash: r.Hash, HashVersion: r.HashVersion, TimestampMs: r.TimestampMs, Fields: r.Fields}
	}
	return Log{Source: rows, SaltKey: []byte(f.HMACKey)}
}

func parseReceipt(t *testing.T, raw json.RawMessage) Receipt {
	t.Helper()
	var r Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func sameJSON(t *testing.T, a, b any) bool {
	t.Helper()
	var x, y any
	for i, v := range []any{a, b} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		dst := &x
		if i == 1 {
			dst = &y
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatal(err)
		}
	}
	return reflect.DeepEqual(x, y)
}

// TestTSFixtureVerifies checks that everything the TypeScript SDK produced
// verifies in Go with the same outcome the TypeScript verifier gave.
func TestTSFixtureVerifies(t *testing.T) {
	f := loadTS(t)
	for i, c := range f.Inclusion {
		if got := VerifyInclusionProof(c.Proof, c.Checkpoint, f.PublicKeys...); got != c.Expected.outcome() {
			t.Errorf("inclusion %d: got %+v want %+v", i, got, c.Expected)
		}
	}
	if got := VerifyConsistencyProof(f.Consistency.Proof, f.Consistency.Older, f.Consistency.Newer, f.PublicKeys...); got != f.Consistency.Expected.outcome() {
		t.Errorf("consistency: got %+v", got)
	}
	for _, r := range f.Receipts {
		if got := VerifyReceipt(parseReceipt(t, r.Receipt), f.PublicKeys...); got != r.Expected.outcome() {
			t.Errorf("receipt %q: got %+v want %+v", r.Name, got, r.Expected)
		}
	}
	for _, n := range f.Negative {
		t.Run(n.Name, func(t *testing.T) {
			var got Outcome
			switch n.Kind {
			case "checkpoint":
				got = VerifyCheckpoint(n.Checkpoint, n.Keys...)
			case "inclusion":
				var p InclusionProof
				if err := json.Unmarshal(n.Proof, &p); err != nil {
					t.Fatal(err)
				}
				got = VerifyInclusionProof(p, n.Checkpoint, n.Keys...)
			case "consistency":
				var p ConsistencyProof
				if err := json.Unmarshal(n.Proof, &p); err != nil {
					t.Fatal(err)
				}
				got = VerifyConsistencyProof(p, n.Older, n.Newer, n.Keys...)
			case "receipt":
				got = VerifyReceipt(parseReceipt(t, n.Receipt), n.Keys...)
			default:
				t.Fatalf("unknown kind %q", n.Kind)
			}
			if got != n.Expected.outcome() {
				t.Errorf("got %+v want %+v", got, n.Expected)
			}
		})
	}
}

// TestTSFixtureRebuilt rebuilds every artifact from the TypeScript rows and requires exact
// equality. Equal Ed25519 signatures prove the signed bytes match.
func TestTSFixtureRebuilt(t *testing.T) {
	f := loadTS(t)
	lg := f.log()
	ctx := context.Background()
	s1 := signerFromD(t, f.PrivateKeys["k1"].D, "k1")
	s2 := signerFromD(t, f.PrivateKeys["k2"].D, "k2")

	// cp1 covered the first 6 rows only; later rows have later timestamps, so
	// bounding by Until reproduces it.
	until := time.UnixMilli(f.Rows[5].TimestampMs)
	cp1, err := CreateCheckpoint(ctx, lg, CreateOptions{Signer: s1, Now: time.UnixMilli(f.Now1), Until: &until})
	if err != nil {
		t.Fatal(err)
	}
	cp1ts := f.Checkpoints["cp1"]
	// The TS cp1 had no until; compare the unsigned fields that must agree.
	if cp1.Size != cp1ts.Size || cp1.RootHash != cp1ts.RootHash {
		t.Fatalf("cp1 size/root differ: go %d %s ts %d %s", cp1.Size, cp1.RootHash, cp1ts.Size, cp1ts.RootHash)
	}
	cp2, err := CreateCheckpoint(ctx, lg, CreateOptions{Signer: s2, Now: time.UnixMilli(f.Now2)})
	if err != nil {
		t.Fatal(err)
	}
	if cp2 != f.Checkpoints["cp2"] {
		t.Fatalf("cp2 differs\n go %+v\n ts %+v", cp2, f.Checkpoints["cp2"])
	}
	for _, c := range f.Inclusion {
		p, err := CreateInclusionProof(ctx, lg, c.Proof.RowID, cp2)
		if err != nil {
			t.Fatal(err)
		}
		if !sameJSON(t, p, c.Proof) {
			t.Errorf("inclusion proof for %s differs", c.Proof.RowID)
		}
	}
	cons, err := CreateConsistencyProof(ctx, lg, cp1ts, cp2)
	if err != nil {
		t.Fatal(err)
	}
	if !sameJSON(t, cons, f.Consistency.Proof) {
		t.Error("consistency proof differs")
	}
	for _, r := range f.Receipts {
		want := parseReceipt(t, r.Receipt)
		reveal := make([]string, 0, len(want.Decision.Revealed))
		for k := range want.Decision.Revealed {
			reveal = append(reveal, k)
		}
		got, err := CreateReceipt(ctx, lg, want.Decision.RowID, want.Checkpoint, reveal)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		if !sameJSON(t, got, want) {
			gj, _ := json.Marshal(got)
			t.Errorf("receipt %q differs\n go %s\n ts %s", r.Name, gj, r.Receipt)
		}
	}
}

// goFixture is the shape of testdata/go-fixture.json, checked by the
// TypeScript verifier (testdata/verify-go-fixture.ts).
type goFixture struct {
	Note        string                `json:"note"`
	PublicKeys  []PublicKey           `json:"publicKeys"`
	Checkpoints map[string]Checkpoint `json:"checkpoints"`
	Inclusion   []goInclusion         `json:"inclusion"`
	Consistency goConsistency         `json:"consistency"`
	Receipts    []goReceipt           `json:"receipts"`
	Negative    []goNegative          `json:"negative"`
}

type goInclusion struct {
	Proof      InclusionProof `json:"proof"`
	Checkpoint Checkpoint     `json:"checkpoint"`
}

type goConsistency struct {
	Proof ConsistencyProof `json:"proof"`
	Older Checkpoint       `json:"older"`
	Newer Checkpoint       `json:"newer"`
}

type goReceipt struct {
	Name    string  `json:"name"`
	Receipt Receipt `json:"receipt"`
}

type goNegative struct {
	Name           string      `json:"name"`
	Kind           string      `json:"kind"`
	Checkpoint     *Checkpoint `json:"checkpoint,omitempty"`
	Proof          any         `json:"proof,omitempty"`
	Older          *Checkpoint `json:"older,omitempty"`
	Newer          *Checkpoint `json:"newer,omitempty"`
	Receipt        *Receipt    `json:"receipt,omitempty"`
	Keys           []PublicKey `json:"keys"`
	ExpectedReason Reason      `json:"expectedReason"`
}

func goRows() StaticSource {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	var rows StaticSource
	for i := 1; i <= 20; i++ {
		id := fmt.Sprintf("g%02d", i)
		sum := sha256.Sum256([]byte("row-hash:" + id))
		fields := map[string]any{
			"id": id, "action": "execute", "resource": "mcp:payments:refund",
			"parameters": map[string]any{"orderId": i, "amount": 12.5 * float64(i), "note": "café   \"x\" <&>", "tags": []any{"a", nil, true}},
			"result":     "allowed", "reason": nil, "durationMs": 7, "tokensCost": nil, "ip": "10.0.0.1", "userAgent": nil,
			"cacheHit": i%2 == 0, "timestamp": base + int64(i)*1000, "policyVersion": "p1",
			"delegationChain": nil, "inputProvenance": nil, "idPseudonyms": map[string]any{"userId": "ab" + id},
		}
		rows = append(rows, Row{ID: id, Hash: hex.EncodeToString(sum[:]), HashVersion: 2, TimestampMs: base + int64(i)*1000, Fields: fields})
	}
	return rows
}

// TestWriteGoFixture regenerates testdata/go-fixture.json when THEAUTH_WRITE_GO_FIXTURE=1, and
// otherwise checks the committed fixture verifies.
func TestWriteGoFixture(t *testing.T) {
	ctx := context.Background()
	lg := Log{Source: goRows(), SaltKey: []byte("go-interop-fixture-key")}
	seed := sha256.Sum256([]byte("theauth go interop fixture signing seed"))
	signer, err := NewEd25519Signer(ed25519.NewKeyFromSeed(seed[:]), "go-1")
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := GenerateKeyPair("go-2")
	keys := []PublicKey{signer.PublicKey()}
	t0 := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	// The older checkpoint covers the first 7 rows.
	older, err := CreateCheckpoint(ctx, Log{Source: goRows()[:7], SaltKey: lg.SaltKey}, CreateOptions{Signer: signer, Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	cp2, err := CreateCheckpoint(ctx, lg, CreateOptions{Signer: signer, Now: t0.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	fx := goFixture{
		Note:        "Generated by Go (audit/checkpoint). Verified by testdata/verify-go-fixture.ts against the TypeScript SDK. See testdata/README.md.",
		PublicKeys:  keys,
		Checkpoints: map[string]Checkpoint{"cp1": older, "cp2": cp2},
	}
	for i := range goRows() {
		p, err := CreateInclusionProof(ctx, lg, fmt.Sprintf("g%02d", i+1), cp2)
		if err != nil {
			t.Fatal(err)
		}
		fx.Inclusion = append(fx.Inclusion, goInclusion{Proof: p, Checkpoint: cp2})
	}
	cons, err := CreateConsistencyProof(ctx, lg, older, cp2)
	if err != nil {
		t.Fatal(err)
	}
	fx.Consistency = goConsistency{Proof: cons, Older: older, Newer: cp2}
	for _, c := range []struct {
		name, row string
		reveal    []string
	}{
		{"parameters revealed", "g03", []string{"action", "parameters", "result", "timestamp", "cacheHit"}},
		{"nothing revealed", "g04", nil},
		{"all revealed", "g05", FieldsV2},
	} {
		r, err := CreateReceipt(ctx, lg, c.row, cp2, c.reveal)
		if err != nil {
			t.Fatal(err)
		}
		fx.Receipts = append(fx.Receipts, goReceipt{Name: c.name, Receipt: r})
	}
	rc := fx.Receipts[0].Receipt
	rcValue := cloneReceipt(t, rc)
	rcValue.Decision.Revealed["result"] = RevealedField{Value: "denied", Salt: rc.Decision.Revealed["result"].Salt}
	rcAlg := cloneReceipt(t, rc)
	rcAlg.Checkpoint.Alg = "none"
	cpAlg, cpKey, cpSig, cpRoot := cp2, cp2, cp2, cp2
	cpAlg.Alg = "HS256"
	cpKey.KeyID = "go-9"
	cpSig.Signature = cp2.Signature[:len(cp2.Signature)-2] + "AA"
	cpRoot.RootHash = hex.EncodeToString(make([]byte, 32))
	badPath := fx.Inclusion[4].Proof
	badPath.Path = slices.Clone(badPath.Path)
	badPath.Path[0] = hex.EncodeToString(make([]byte, 32))
	badCons := cons
	badCons.Path = slices.Clone(cons.Path)
	badCons.Path[0] = hex.EncodeToString(make([]byte, 32))
	fx.Negative = []goNegative{
		{Name: "alg HS256", Kind: "checkpoint", Checkpoint: &cpAlg, Keys: keys, ExpectedReason: ReasonUnsupportedAlg},
		{Name: "unknown keyId", Kind: "checkpoint", Checkpoint: &cpKey, Keys: keys, ExpectedReason: ReasonUnknownKey},
		{Name: "bad signature", Kind: "checkpoint", Checkpoint: &cpSig, Keys: keys, ExpectedReason: ReasonBadSignature},
		{Name: "root tampered", Kind: "checkpoint", Checkpoint: &cpRoot, Keys: keys, ExpectedReason: ReasonBadSignature},
		{Name: "wrong key", Kind: "checkpoint", Checkpoint: &cp2, Keys: []PublicKey{other.PublicKey()}, ExpectedReason: ReasonUnknownKey},
		{Name: "inclusion path tampered", Kind: "inclusion", Proof: badPath, Checkpoint: &cp2, Keys: keys, ExpectedReason: ReasonBadProof},
		{Name: "consistency path tampered", Kind: "consistency", Proof: badCons, Older: &older, Newer: &cp2, Keys: keys, ExpectedReason: ReasonBadProof},
		{Name: "receipt value changed", Kind: "receipt", Receipt: &rcValue, Keys: keys, ExpectedReason: ReasonLeafMismatch},
		{Name: "receipt alg none", Kind: "receipt", Receipt: &rcAlg, Keys: keys, ExpectedReason: ReasonUnsupportedAlg},
	}
	// Whatever is written must verify here first.
	for _, n := range fx.Negative {
		if got := goNegativeOutcome(n); got.Reason != n.ExpectedReason {
			t.Fatalf("%s: go says %+v want %s", n.Name, got, n.ExpectedReason)
		}
	}
	for _, c := range fx.Inclusion {
		if !VerifyInclusionProof(c.Proof, c.Checkpoint, keys...).Valid {
			t.Fatal("own inclusion proof invalid")
		}
	}
	if os.Getenv("THEAUTH_WRITE_GO_FIXTURE") != "1" {
		return
	}
	raw, err := json.MarshalIndent(fx, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("testdata/go-fixture.json", append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func goNegativeOutcome(n goNegative) Outcome {
	switch n.Kind {
	case "checkpoint":
		return VerifyCheckpoint(*n.Checkpoint, n.Keys...)
	case "inclusion":
		return VerifyInclusionProof(n.Proof.(InclusionProof), *n.Checkpoint, n.Keys...)
	case "consistency":
		return VerifyConsistencyProof(n.Proof.(ConsistencyProof), *n.Older, *n.Newer, n.Keys...)
	}
	return VerifyReceipt(*n.Receipt, n.Keys...)
}

func cloneReceipt(t *testing.T, r Receipt) Receipt {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var out Receipt
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
