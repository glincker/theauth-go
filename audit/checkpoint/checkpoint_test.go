package checkpoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/oklog/ulid/v2"
)

func leavesN(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = LeafHash([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	return out
}

func TestMerkleMatchesTSVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/ts-merkle-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		EmptyRoot string `json:"emptyRoot"`
		Vectors   []struct {
			Size              int    `json:"size"`
			Root              string `json:"root"`
			InclusionDigest   string `json:"inclusionDigest"`
			ConsistencyDigest string `json:"consistencyDigest"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(MerkleRoot(nil)); got != v.EmptyRoot {
		t.Fatalf("empty root %s want %s", got, v.EmptyRoot)
	}
	for _, c := range v.Vectors {
		ls := leavesN(c.Size)
		if got := hex.EncodeToString(MerkleRoot(ls)); got != c.Root {
			t.Errorf("size %d root %s want %s", c.Size, got, c.Root)
		}
		inc, con := sha256.New(), sha256.New()
		for i := 0; i < c.Size; i++ {
			p, _ := InclusionPath(ls, i)
			for _, h := range p {
				inc.Write(h)
			}
		}
		for m := 0; m <= c.Size; m++ {
			p, _ := ConsistencyPath(ls, m)
			for _, h := range p {
				con.Write(h)
			}
		}
		if got := hex.EncodeToString(inc.Sum(nil)); got != c.InclusionDigest {
			t.Errorf("size %d inclusion digest differs from TS", c.Size)
		}
		if got := hex.EncodeToString(con.Sum(nil)); got != c.ConsistencyDigest {
			t.Errorf("size %d consistency digest differs from TS", c.Size)
		}
	}
}

func TestRFC6962KnownRoots(t *testing.T) {
	// Single leaf with empty data and the empty tree (RFC 6962 test vectors).
	if got := hex.EncodeToString(LeafHash(nil)); got != "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" {
		t.Fatalf("empty leaf hash %s", got)
	}
	if got := hex.EncodeToString(MerkleRoot(nil)); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty root %s", got)
	}
}

func TestProofsAllSizes(t *testing.T) {
	for n := 1; n <= 33; n++ {
		ls := leavesN(n)
		root := MerkleRoot(ls)
		for i := 0; i < n; i++ {
			path, err := InclusionPath(ls, i)
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyInclusionPath(ls[i], int64(i), int64(n), path, root) {
				t.Fatalf("n=%d i=%d: inclusion rejected", n, i)
			}
			if i+1 < n && VerifyInclusionPath(ls[i], int64(i+1), int64(n), path, root) {
				t.Fatalf("n=%d i=%d: wrong index accepted", n, i)
			}
			if n > 1 && VerifyInclusionPath(ls[i], int64(i), int64(n), path[:len(path)-1], root) {
				t.Fatalf("n=%d i=%d: short path accepted", n, i)
			}
			if len(path) > 0 {
				bad := append([][]byte{append([]byte(nil), path[0]...)}, path[1:]...)
				bad[0][0] ^= 1
				if VerifyInclusionPath(ls[i], int64(i), int64(n), bad, root) {
					t.Fatalf("n=%d i=%d: flipped path accepted", n, i)
				}
			}
		}
		for m := 0; m <= n; m++ {
			path, err := ConsistencyPath(ls, m)
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyConsistencyPath(int64(m), int64(n), MerkleRoot(ls[:m]), root, path) {
				t.Fatalf("n=%d m=%d: consistency rejected", n, m)
			}
			if m > 0 && m < n {
				other := leavesN(n)
				other[m-1] = LeafHash([]byte("rewritten"))
				if VerifyConsistencyPath(int64(m), int64(n), MerkleRoot(other[:m]), root, path) {
					t.Fatalf("n=%d m=%d: rewritten old leaf accepted", n, m)
				}
				if len(path) > 0 && VerifyConsistencyPath(int64(m), int64(n), MerkleRoot(ls[:m]), root, path[:len(path)-1]) {
					t.Fatalf("n=%d m=%d: short consistency path accepted", n, m)
				}
			}
		}
	}
}

func TestCanonicalJSON(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, "null"},
		{"sorted keys", map[string]any{"b": 1, "a": []any{2, "x"}}, `{"a":[2,"x"],"b":1}`},
		{"code unit order", map[string]any{"\U0001F600": 1, "～": 2}, "{\"\U0001F600\":1,\"～\":2}"},
		{"floats", []any{1.5, 1e21, 1e-7, -0.25, 100.0, 0.000001, float64(1 << 53)}, `[1.5,1e+21,1e-7,-0.25,100,0.000001,9007199254740992]`},
		{"json number", json.Number("1E3"), "1000"},
		{"escapes", "a\"b\\c\n\t\u0001\u007f<>& ", "\"a\\\"b\\\\c\\n\\t\\u0001\u007f<>& \""},
		{"negative zero", math.Copysign(0, -1), "0"},
		{"struct fallback", struct {
			B int `json:"b"`
			A int `json:"a"`
		}{1, 2}, `{"a":2,"b":1}`},
	}
	for _, c := range cases {
		got, err := CanonicalJSON(c.in)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q err %v want %q", c.name, got, err, c.want)
		}
	}
}

func testLog(n int) (Log, *Ed25519Signer, PublicKey) {
	rows := make(StaticSource, n)
	for i := range rows {
		id := fmt.Sprintf("row-%03d", i)
		sum := sha256.Sum256([]byte(id))
		rows[i] = Row{ID: id, Hash: hex.EncodeToString(sum[:]), HashVersion: 2, TimestampMs: 1_000_000 + int64(i)*1000,
			Fields: map[string]any{"id": id, "action": "execute", "parameters": map[string]any{"i": i}, "result": "allowed"}}
	}
	s, pub, _ := GenerateKeyPair("k1")
	return Log{Source: rows, SaltKey: []byte("salt-key")}, s, pub
}

func TestLogSizes(t *testing.T) {
	ctx := context.Background()
	for n := 1; n <= 33; n++ {
		lg, signer, pub := testLog(n)
		cp, err := CreateCheckpoint(ctx, lg, CreateOptions{Signer: signer})
		if err != nil || cp.Size != int64(n) {
			t.Fatalf("n=%d: %v size %d", n, err, cp.Size)
		}
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("row-%03d", i)
			p, err := CreateInclusionProof(ctx, lg, id, cp)
			if err != nil {
				t.Fatal(err)
			}
			if o := VerifyInclusionProof(p, cp, pub); !o.Valid {
				t.Fatalf("n=%d i=%d: %+v", n, i, o)
			}
			if i%7 == 0 {
				r, err := CreateReceipt(ctx, lg, id, cp, []string{"action", "result"})
				if err != nil {
					t.Fatal(err)
				}
				if o := VerifyReceipt(r, pub); !o.Valid {
					t.Fatalf("receipt n=%d i=%d: %+v", n, i, o)
				}
			}
		}
		for m := 0; m <= n; m++ {
			old, err := CreateCheckpoint(ctx, Log{Source: lg.Source.(StaticSource)[:m], SaltKey: lg.SaltKey}, CreateOptions{Signer: signer})
			if err != nil {
				t.Fatal(err)
			}
			cons, err := CreateConsistencyProof(ctx, lg, old, cp)
			if err != nil {
				t.Fatalf("n=%d m=%d: %v", n, m, err)
			}
			if o := VerifyConsistencyProof(cons, old, cp, pub); !o.Valid {
				t.Fatalf("n=%d m=%d: %+v", n, m, o)
			}
		}
	}
}

func TestEmptyLog(t *testing.T) {
	ctx := context.Background()
	lg, signer, pub := testLog(0)
	cp, err := CreateCheckpoint(ctx, lg, CreateOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	if cp.Size != 0 || cp.RootHash != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty checkpoint %+v", cp)
	}
	if !VerifyCheckpoint(cp, pub).Valid {
		t.Fatal("empty checkpoint rejected")
	}
	if _, err := CreateInclusionProof(ctx, lg, "x", cp); !errors.Is(err, ErrRowNotFound) {
		t.Fatalf("want ROW_NOT_FOUND, got %v", err)
	}
	if o := VerifyInclusionProof(InclusionProof{Version: 1, RowID: "x", TreeSize: 0, LeafHash: strings.Repeat("0", 64), Path: []string{}}, cp, pub); o.Valid {
		t.Fatal("inclusion in empty tree accepted")
	}
}

func TestRowsAfterCheckpoint(t *testing.T) {
	ctx := context.Background()
	lg, signer, pub := testLog(10)
	all := lg.Source.(StaticSource)
	early := Log{Source: all[:6], SaltKey: lg.SaltKey}
	cp, _ := CreateCheckpoint(ctx, early, CreateOptions{Signer: signer})
	// Appended rows do not break proofs against the old checkpoint.
	p, err := CreateInclusionProof(ctx, lg, "row-002", cp)
	if err != nil || !VerifyInclusionProof(p, cp, pub).Valid {
		t.Fatalf("append broke an old proof: %v", err)
	}
	if _, err := CreateInclusionProof(ctx, lg, "row-008", cp); !errors.Is(err, ErrRowNotFound) {
		t.Fatalf("row past the checkpoint: %v", err)
	}
	// A row that lands inside the covered range afterwards is detected.
	inserted := append(StaticSource{}, all...)
	inserted = append(inserted, Row{ID: "row-late", Hash: strings.Repeat("a", 64), HashVersion: 2, TimestampMs: all[2].TimestampMs, Fields: map[string]any{}})
	if _, err := CreateInclusionProof(ctx, Log{Source: inserted, SaltKey: lg.SaltKey}, "row-002", cp); !errors.Is(err, ErrLogMismatch) {
		t.Fatalf("backdated row: %v", err)
	}
	// Rewriting a covered row is detected.
	edited := append(StaticSource{}, all...)
	edited[1].Fields = map[string]any{"id": "row-001", "action": "other"}
	if _, err := CreateInclusionProof(ctx, Log{Source: edited, SaltKey: lg.SaltKey}, "row-002", cp); !errors.Is(err, ErrLogMismatch) {
		t.Fatalf("edited row: %v", err)
	}
	// Shrunk log.
	if _, err := CreateInclusionProof(ctx, Log{Source: all[:3], SaltKey: lg.SaltKey}, "row-001", cp); !errors.Is(err, ErrLogMismatch) {
		t.Fatalf("shrunk log: %v", err)
	}
	// Consistency across a log that was rewritten under the older checkpoint.
	newer, _ := CreateCheckpoint(ctx, Log{Source: edited, SaltKey: lg.SaltKey}, CreateOptions{Signer: signer})
	if _, err := CreateConsistencyProof(ctx, Log{Source: edited, SaltKey: lg.SaltKey}, cp, newer); !errors.Is(err, ErrLogMismatch) {
		t.Fatalf("rewritten prefix: %v", err)
	}
	if _, err := CreateConsistencyProof(ctx, lg, newer, cp); !errors.Is(err, ErrInvalidOrder) {
		t.Fatalf("order: %v", err)
	}
	// Scoped checkpoints with different since do not mix.
	since := time.UnixMilli(all[2].TimestampMs)
	scoped, _ := CreateCheckpoint(ctx, lg, CreateOptions{Signer: signer, Since: &since})
	if _, err := CreateConsistencyProof(ctx, lg, cp, scoped); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("scope: %v", err)
	}
}

func TestVerifyRejections(t *testing.T) {
	ctx := context.Background()
	lg, signer, pub := testLog(9)
	cp, _ := CreateCheckpoint(ctx, lg, CreateOptions{Signer: signer})
	_, otherPub, _ := GenerateKeyPair("k1") // same id, different key
	_, rotatedPub, _ := GenerateKeyPair("k2")
	mut := func(f func(c *Checkpoint)) Checkpoint { c := cp; f(&c); return c }
	cases := []struct {
		name string
		cp   Checkpoint
		keys []PublicKey
		want Reason
	}{
		{"ok", cp, []PublicKey{pub}, ""},
		{"ok in key set", cp, []PublicKey{rotatedPub, pub}, ""},
		{"wrong key same id", cp, []PublicKey{otherPub}, ReasonBadSignature},
		{"no matching key id", cp, []PublicKey{rotatedPub}, ReasonUnknownKey},
		{"no keys", cp, nil, ReasonUnknownKey},
		{"alg none", mut(func(c *Checkpoint) { c.Alg = "none" }), []PublicKey{pub}, ReasonUnsupportedAlg},
		{"alg HS256", mut(func(c *Checkpoint) { c.Alg = "HS256" }), []PublicKey{pub}, ReasonUnsupportedAlg},
		{"alg lowercase", mut(func(c *Checkpoint) { c.Alg = "ed25519" }), []PublicKey{pub}, ReasonUnsupportedAlg},
		{"keyId swapped", mut(func(c *Checkpoint) { c.KeyID = "k2" }), []PublicKey{pub, rotatedPub}, ReasonBadSignature},
		{"root tampered", mut(func(c *Checkpoint) { c.RootHash = strings.Repeat("0", 64) }), []PublicKey{pub}, ReasonBadSignature},
		{"size tampered", mut(func(c *Checkpoint) { c.Size++ }), []PublicKey{pub}, ReasonBadSignature},
		{"timestamp tampered", mut(func(c *Checkpoint) { c.Timestamp++ }), []PublicKey{pub}, ReasonBadSignature},
		{"until tampered", mut(func(c *Checkpoint) { v := int64(5); c.Until = &v }), []PublicKey{pub}, ReasonBadSignature},
		{"short signature", mut(func(c *Checkpoint) { c.Signature = c.Signature[:20] }), []PublicKey{pub}, ReasonBadSignature},
		{"padded signature", mut(func(c *Checkpoint) { c.Signature += "=" }), []PublicKey{pub}, ReasonBadSignature},
		{"uppercase root", mut(func(c *Checkpoint) { c.RootHash = strings.ToUpper(c.RootHash) }), []PublicKey{pub}, ReasonMalformed},
		{"version 2", mut(func(c *Checkpoint) { c.Version = 2 }), []PublicKey{pub}, ReasonMalformed},
		{"negative size", mut(func(c *Checkpoint) { c.Size = -1 }), []PublicKey{pub}, ReasonMalformed},
	}
	for _, c := range cases {
		o := VerifyCheckpoint(c.cp, c.keys...)
		if c.want == "" && !o.Valid || c.want != "" && (o.Valid || o.Reason != c.want) {
			t.Errorf("%s: got %+v want %q", c.name, o, c.want)
		}
	}
	jwkBad := pub
	jwkBad.PublicKey.Crv = "P-256"
	if o := VerifyCheckpoint(cp, jwkBad); o.Reason != ReasonUnsupportedAlg {
		t.Errorf("jwk crv: %+v", o)
	}
	jwkBad = pub
	jwkBad.PublicKey.X = "AAAA"
	if o := VerifyCheckpoint(cp, jwkBad); o.Reason != ReasonBadSignature {
		t.Errorf("jwk x: %+v", o)
	}
}

func TestReceiptRules(t *testing.T) {
	ctx := context.Background()
	lg, signer, pub := testLog(12)
	cp, _ := CreateCheckpoint(ctx, lg, CreateOptions{Signer: signer})
	r, err := CreateReceipt(ctx, lg, "row-005", cp, []string{"action", "parameters"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Decision.Commitments["parameters"]; ok {
		t.Fatal("revealed field also committed")
	}
	if _, err := CreateReceipt(ctx, lg, "row-005", cp, []string{"agentId"}); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("v1 field on v2 row: %v", err)
	}
	if _, err := CreateReceipt(ctx, lg, "nope", cp, nil); !errors.Is(err, ErrRowNotFound) {
		t.Fatalf("unknown row: %v", err)
	}
	cases := map[string]func(r *Receipt) Reason{
		"value changed": func(r *Receipt) Reason {
			r.Decision.Revealed["action"] = RevealedField{Value: "x", Salt: r.Decision.Revealed["action"].Salt}
			return ReasonLeafMismatch
		},
		"salt changed": func(r *Receipt) Reason {
			f := r.Decision.Revealed["action"]
			f.Salt = strings.Repeat("1", 64)
			r.Decision.Revealed["action"] = f
			return ReasonLeafMismatch
		},
		"row hash": func(r *Receipt) Reason { r.Decision.RowHash = strings.Repeat("2", 64); return ReasonLeafMismatch },
		"commitment": func(r *Receipt) Reason {
			r.Decision.Commitments["result"] = strings.Repeat("3", 64)
			return ReasonLeafMismatch
		},
		"extra field": func(r *Receipt) Reason {
			r.Decision.Commitments["bogus"] = strings.Repeat("3", 64)
			return ReasonMalformed
		},
		"hash version":    func(r *Receipt) Reason { r.Decision.HashVersion = 1; return ReasonMalformed },
		"row id mismatch": func(r *Receipt) Reason { r.Proof.RowID = "other"; return ReasonMalformed },
		"bad salt hex": func(r *Receipt) Reason {
			f := r.Decision.Revealed["action"]
			f.Salt = "zz"
			r.Decision.Revealed["action"] = f
			return ReasonMalformed
		},
		"nil maps":    func(r *Receipt) Reason { r.Decision.Revealed = nil; return ReasonMalformed },
		"alg none":    func(r *Receipt) Reason { r.Checkpoint.Alg = "none"; return ReasonUnsupportedAlg },
		"proof index": func(r *Receipt) Reason { r.Proof.LeafIndex++; return ReasonBadProof },
	}
	for name, mutate := range cases {
		c := cloneReceipt(t, r)
		want := mutate(&c)
		if o := VerifyReceipt(c, pub); o.Valid || o.Reason != want {
			t.Errorf("%s: got %+v want %s", name, o, want)
		}
	}
	_, wrong, _ := GenerateKeyPair("k1")
	if o := VerifyReceipt(r, wrong); o.Valid || o.Reason != ReasonBadSignature {
		t.Errorf("wrong key: %+v", o)
	}
}

func TestStrictJSON(t *testing.T) {
	for _, in := range []string{
		`{"version":1,"alg":"Ed25519","keyId":"k","size":1,"rootHash":"` + strings.Repeat("0", 64) + `","timestamp":1,"since":null,"until":null}`,
		`{"version":1,"alg":"Ed25519","keyId":"k","size":1.5,"rootHash":"x","timestamp":1,"since":null,"until":null,"signature":"s"}`,
		`{"version":1,"alg":null,"keyId":"k","size":1,"rootHash":"x","timestamp":1,"since":null,"until":null,"signature":"s"}`,
	} {
		var c Checkpoint
		if err := json.Unmarshal([]byte(in), &c); err == nil {
			t.Errorf("accepted %s", in)
		}
	}
	var p InclusionProof
	if err := json.Unmarshal([]byte(`{"version":1,"rowId":"a","leafIndex":0,"treeSize":1,"leafHash":"`+strings.Repeat("0", 64)+`"}`), &p); err == nil {
		t.Error("proof without path accepted")
	}
}

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	if _, ok, _ := s.Latest(ctx); ok {
		t.Fatal("empty store has a latest")
	}
	lg, signer, _ := testLog(8)
	mk := func(n int, ts int64) Checkpoint {
		c, err := CreateCheckpoint(ctx, Log{Source: lg.Source.(StaticSource)[:n], SaltKey: lg.SaltKey}, CreateOptions{Signer: signer, Now: time.UnixMilli(ts), Store: s})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	a, b, c := mk(5, 300), mk(3, 100), mk(5, 200)
	_ = mk(5, 300) // duplicate, no op
	list, _ := s.List(ctx)
	if len(list) != 3 || list[0].Size != 3 || list[1] != c || list[2] != a {
		t.Fatalf("list order: %+v", list)
	}
	if latest, ok, _ := s.Latest(ctx); !ok || latest != a {
		t.Fatalf("latest %+v", latest)
	}
	if got, _ := s.BySize(ctx, 5); len(got) != 2 || got[0] != c {
		t.Fatalf("bySize %+v", got)
	}
	if got, _ := s.BySize(ctx, 4); len(got) != 0 {
		t.Fatal("bySize 4")
	}
	_ = b
}

type fakeStore struct{ events []models.AuditEvent }

func (f fakeStore) QueryAuditEvents(_ context.Context, q models.AuditQuery) ([]models.AuditEvent, string, error) {
	start := 0
	if q.After != "" {
		if _, err := fmt.Sscanf(q.After, "%d", &start); err != nil {
			return nil, "", err
		}
	}
	end := start + q.Limit
	if end >= len(f.events) {
		return f.events[start:], "", nil
	}
	return f.events[start:end], fmt.Sprint(end), nil
}

func TestEventSourceWithRealChain(t *testing.T) {
	ctx := context.Background()
	secret := []byte("installation-secret")
	var events []models.AuditEvent
	head := audit.ChainHead{}
	base := time.Date(2026, 10, 1, 12, 0, 0, 123456000, time.UTC)
	for i := 0; i < 23; i++ {
		e := models.AuditEvent{
			ID: ulid.Make(), Action: "user.login", TargetType: "user", TargetID: fmt.Sprint(i),
			Metadata: map[string]any{"n": i, "ua": "x<y>"}, IP: "10.0.0.1", CreatedAt: base.Add(time.Duration(i) * time.Second),
			SubjectID: "sub", ActorID: "act", DelegationChain: []string{"a", "b"},
		}
		ce, err := audit.BuildChainEntry(e, secret, head)
		if err != nil {
			t.Fatal(err)
		}
		e.Hash, e.PrevHash, e.ChainSeq = ce.Hash, head.Hash, uint64(head.Seq+1)
		head = audit.ChainHead{Seq: head.Seq + 1, Hash: ce.Hash}
		events = append(events, e)
	}
	events = append(events, models.AuditEvent{ID: ulid.Make(), Action: "unchained", CreatedAt: base}) // no hash: skipped
	lg := Log{Source: EventSource{Store: fakeStore{events}, PageSize: 5}, SaltKey: secret}
	signer, pub, _ := GenerateKeyPair("chain-1")
	cp, err := CreateCheckpoint(ctx, lg, CreateOptions{Signer: signer})
	if err != nil || cp.Size != 23 {
		t.Fatalf("checkpoint: %v size %d", err, cp.Size)
	}
	for _, e := range []models.AuditEvent{events[0], events[11], events[22]} {
		r, err := CreateReceipt(ctx, lg, e.ID.String(), cp, []string{"action", "targetId", "metadata"})
		if err != nil {
			t.Fatal(err)
		}
		if r.Decision.HashVersion != GoChainHashVersion || r.Decision.RowHash != e.Hash {
			t.Fatalf("receipt does not carry the chain hash: %+v", r.Decision)
		}
		raw, _ := json.Marshal(r)
		var back Receipt
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		if o := VerifyReceipt(back, pub); !o.Valid {
			t.Fatalf("event receipt: %+v", o)
		}
	}
	// A tampered chained row (hash edited in the store) breaks the checkpoint.
	events[4].Hash = strings.Repeat("9", 64)
	if _, err := CreateInclusionProof(ctx, lg, events[0].ID.String(), cp); !errors.Is(err, ErrLogMismatch) {
		t.Fatalf("tampered row: %v", err)
	}
}
