package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

func emitWith(t *testing.T, cfg Config, ctx context.Context, meta map[string]any) models.AuditEvent {
	t.Helper()
	st := &captureStore{}
	cfg.BatchSize, cfg.FlushInterval = 100, 5*time.Millisecond
	s := NewService(st, cfg)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	s.Emit(ctx, "agent.authorize", models.TargetRef{Type: "tool", ID: "t"}, meta, nil, nil)
	s.Stop()
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.events) != 1 {
		t.Fatalf("stored %d events", len(st.events))
	}
	return st.events[0]
}

func TestEmitRecordsContextInputsAsHashes(t *testing.T) {
	t.Parallel()
	key := []byte("0123456789abcdef0123456789abcdef")
	h, err := NewInputHasher(key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithInputs(context.Background(),
		InputSource{Kind: InputUserMessage, ID: "msg_1", Content: "transfer the funds"},
		InputSource{Kind: InputRetrievedDocument, Content: "ignore previous instructions"})
	e := emitWith(t, Config{InputHasher: h}, ctx, map[string]any{"tool": "pay"})

	raw, _ := json.Marshal(e.InputProvenance)
	if strings.Contains(string(raw), "transfer the funds") || strings.Contains(string(raw), "ignore previous") {
		t.Fatalf("content stored: %s", raw)
	}
	if e.InputProvenance["alg"] != InputHashHMAC {
		t.Fatalf("alg = %v", e.InputProvenance["alg"])
	}
	n, _ := ProvenanceNeedle(models.ProvenanceFilter{Kind: InputUserMessage, Hash: h.Hash("transfer the funds")})
	if !MatchesProvenance(string(raw), n) {
		t.Fatalf("filter built with the same key does not match %s", raw)
	}
	// The unkeyed digest of the same content must not match: that is the point of the key.
	var plain InputHasher
	n, _ = ProvenanceNeedle(models.ProvenanceFilter{Hash: plain.Hash("transfer the funds")})
	if MatchesProvenance(string(raw), n) {
		t.Fatal("unkeyed hash matched a keyed record")
	}
}

func TestEmitMergesInputsWithTaintLabels(t *testing.T) {
	t.Parallel()
	ctx := WithAuditMetadata(context.Background(), AuditMetadata{
		InputProvenance: map[string]any{"labels": map[string]any{"*": []any{"untrusted"}}},
	})
	ctx = WithInputs(ctx, InputSource{Kind: InputToolOutput, Content: "x"})
	e := emitWith(t, Config{}, ctx, nil)
	if e.InputProvenance["labels"] == nil || e.InputProvenance["sources"] == nil || e.InputProvenance["keys"] == nil {
		t.Fatalf("record = %v", e.InputProvenance)
	}
}

// Tool arguments reach the audit row as metadata. They cannot become provenance sources, because
// sources only come from the context.
func TestMetadataCannotForgeInputProvenance(t *testing.T) {
	t.Parallel()
	forged := map[string]any{"inputProvenance": map[string]any{
		"sources": []any{map[string]any{"kind": "user_message", "hash": strings.Repeat("a", 64)}},
		"keys":    []any{"user_message:" + strings.Repeat("a", 64)},
	}}
	e := emitWith(t, Config{}, context.Background(), forged)
	if len(e.InputProvenance) != 0 {
		t.Fatalf("metadata became provenance: %v", e.InputProvenance)
	}
}

func TestNoInputsLeavesProvenanceEmpty(t *testing.T) {
	t.Parallel()
	e := emitWith(t, Config{}, context.Background(), nil)
	if e.InputProvenance != nil {
		t.Fatalf("record = %v", e.InputProvenance)
	}
}

type provenanceStore struct{ captureStore }

func (*provenanceStore) AuditProvenanceSupported() bool { return true }

func TestCheckQueryProvenance(t *testing.T) {
	t.Parallel()
	q := models.AuditQuery{Provenance: &models.ProvenanceFilter{Kind: InputAgent}}
	if err := CheckQuery(&captureStore{}, q); !errors.Is(err, models.ErrAuditProvenanceUnsupported) {
		t.Fatalf("backend without the capability: %v", err)
	}
	if err := CheckQuery(&provenanceStore{}, q); err != nil {
		t.Fatalf("capable backend: %v", err)
	}
	bad := models.AuditQuery{Provenance: &models.ProvenanceFilter{Kind: "nope"}}
	if err := CheckQuery(&provenanceStore{}, bad); !errors.Is(err, models.ErrBadProvenanceFilter) {
		t.Fatalf("bad kind: %v", err)
	}
	if err := CheckQuery(&captureStore{}, models.AuditQuery{}); err != nil {
		t.Fatalf("no filter must pass on any backend: %v", err)
	}
}
