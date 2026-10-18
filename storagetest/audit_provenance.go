package storagetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/audit"
)

// AuditProvenanceCapable is the capability flag for the audit provenance filter. A backend returns
// true from AuditProvenanceSupported once it serves AuditQuery.Provenance as a literal substring
// match on the stored input_provenance (never LIKE, where the underscore in "user_message" is a
// wildcard) and refuses an invalid filter with ErrBadProvenanceFilter.
type AuditProvenanceCapable interface {
	AuditProvenanceSupported() bool
}

// RunAuditProvenance runs the provenance filter contract. It skips when store does not declare
// AuditProvenanceCapable.
func RunAuditProvenance(t *testing.T, store AuditSuiteStorage) {
	t.Helper()
	c, ok := store.(AuditProvenanceCapable)
	if !ok || !c.AuditProvenanceSupported() {
		t.Skip("backend does not declare AuditProvenanceCapable; skipping the provenance filter contract")
	}
	t.Run("AuditProvenance", func(t *testing.T) {
		t.Run("RoundTripAndFilter", func(t *testing.T) { provenanceFilter(t, store) })
		t.Run("InvalidFilterRejected", func(t *testing.T) { provenanceInvalid(t, store) })
	})
}

func provenanceAction() string {
	return fmt.Sprintf("storagetest.provenance.%d", time.Now().UnixNano())
}

func provenanceFilter(t *testing.T, store AuditSuiteStorage) {
	ctx := context.Background()
	action := provenanceAction()
	var h audit.InputHasher
	doc, msg, other := h.Hash("the quarterly report"), h.Hash("approve it"), h.Hash("unrelated")
	rows := []struct {
		inputs []audit.InputSource
	}{
		{[]audit.InputSource{
			{Kind: audit.InputRetrievedDocument, ID: "doc_1", Hash: doc},
			{Kind: audit.InputUserMessage, ID: "msg_1", Hash: msg},
		}},
		{[]audit.InputSource{{Kind: audit.InputToolOutput, Hash: doc}}},
		{[]audit.InputSource{{Kind: audit.InputUserMessage, Hash: other}}},
		{nil},
	}
	for i, r := range rows {
		e := theauth.AuditEvent{
			ID: newID(), Action: action, CreatedAt: time.Now().Add(time.Duration(i) * time.Millisecond),
			InputProvenance: audit.BuildInputProvenance(h, r.inputs),
		}
		if err := store.InsertAuditEvents(ctx, []theauth.AuditEvent{e}); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	count := func(f theauth.AuditProvenanceFilter) int {
		t.Helper()
		got, _, err := store.QueryAuditEvents(ctx, theauth.AuditQuery{Action: action, Provenance: &f, Limit: 50})
		if err != nil {
			t.Fatalf("query %+v: %v", f, err)
		}
		return len(got)
	}
	for _, tc := range []struct {
		name string
		f    theauth.AuditProvenanceFilter
		want int
	}{
		{"kind and hash", theauth.AuditProvenanceFilter{Kind: audit.InputRetrievedDocument, Hash: doc}, 1},
		{"hash only crosses kinds", theauth.AuditProvenanceFilter{Hash: doc}, 2},
		{"kind only", theauth.AuditProvenanceFilter{Kind: audit.InputUserMessage}, 2},
		{"kind with other kinds hash", theauth.AuditProvenanceFilter{Kind: audit.InputToolOutput, Hash: msg}, 0},
		{"unknown hash", theauth.AuditProvenanceFilter{Hash: h.Hash("never recorded")}, 0},
		{"kind not present", theauth.AuditProvenanceFilter{Kind: audit.InputAgent}, 0},
	} {
		if got := count(tc.f); got != tc.want {
			t.Errorf("%s: %d rows, want %d", tc.name, got, tc.want)
		}
	}
	// The record reads back whole.
	got, _, err := store.QueryAuditEvents(ctx, theauth.AuditQuery{
		Action: action, Provenance: &theauth.AuditProvenanceFilter{Kind: audit.InputRetrievedDocument, Hash: doc},
	})
	if err != nil || len(got) != 1 {
		t.Fatalf("read back: %d rows, %v", len(got), err)
	}
	srcs, _ := got[0].InputProvenance["sources"].([]any)
	if len(srcs) != 2 || got[0].InputProvenance["alg"] != audit.InputHashSHA256 {
		t.Fatalf("provenance record = %+v", got[0].InputProvenance)
	}
}

func provenanceInvalid(t *testing.T, store AuditSuiteStorage) {
	for _, f := range []theauth.AuditProvenanceFilter{
		{Kind: "not_a_kind"},
		{Hash: "ABC"},
		{Kind: audit.InputAgent, Hash: "zz"},
	} {
		_, _, err := store.QueryAuditEvents(context.Background(), theauth.AuditQuery{Provenance: &f})
		if !errors.Is(err, theauth.ErrBadProvenanceFilter) {
			t.Errorf("filter %+v: err = %v, want ErrBadProvenanceFilter", f, err)
		}
	}
}
