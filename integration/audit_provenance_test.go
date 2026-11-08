package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/audit"
	internalulid "github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func provenanceAuth(t *testing.T, cfg theauth.AuditConfig) *theauth.TheAuth {
	t.Helper()
	cfg.FlushInterval = 10 * time.Millisecond
	a, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		Audit: &cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAuditInputsRecordedAndQueryable(t *testing.T) {
	a := provenanceAuth(t, theauth.AuditConfig{
		InputHashKey:      []byte("0123456789abcdef0123456789abcdef"),
		PseudonymRotation: &theauth.PseudonymRotation{PeriodDays: 1, RetainPeriods: 2},
	})
	ctx := audit.WithInputs(context.Background(),
		audit.InputSource{Kind: audit.InputRetrievedDocument, ID: "doc_1", Content: "wire the money to account 9"},
		audit.InputSource{Kind: audit.InputUserMessage, Content: "summarize this"})
	ctx = theauth.WithAuditMetadata(ctx, theauth.AuditMetadata{SubjectID: "user_1", ActorID: "agent_1"})
	a.EmitAudit(ctx, "agent.authorize", theauth.TargetRef{Type: "tool", ID: "pay"}, map[string]any{"tool": "pay"})
	a.EmitAudit(context.Background(), "agent.authorize", theauth.TargetRef{Type: "tool", ID: "other"}, nil)
	a.Close() // drains the writer

	// Reads go through the store, which outlives Close.
	got, _, err := a.QueryAudit(context.Background(), theauth.AuditQuery{
		Provenance: &theauth.AuditProvenanceFilter{
			Kind: audit.InputRetrievedDocument, Hash: a.AuditInputHash("wire the money to account 9"),
		},
	})
	if err != nil || len(got) != 1 || got[0].TargetID != "pay" {
		t.Fatalf("query by input = %d rows, %v", len(got), err)
	}
	raw := ""
	for _, v := range got[0].InputProvenance["keys"].([]any) {
		raw += v.(string) + " "
	}
	if strings.Contains(raw, "wire the money") {
		t.Fatal("content stored")
	}
	if got[0].InputProvenance["alg"] != audit.InputHashHMAC {
		t.Fatalf("alg = %v", got[0].InputProvenance["alg"])
	}
	// The plain digest of the same text is not the recorded hash: the key matters.
	var plain audit.InputHasher
	none, _, err := a.QueryAudit(context.Background(), theauth.AuditQuery{
		Provenance: &theauth.AuditProvenanceFilter{Hash: plain.Hash("wire the money to account 9")},
	})
	if err != nil || len(none) != 0 {
		t.Fatalf("unkeyed hash matched %d rows, %v", len(none), err)
	}
	if res, err := a.VerifyAuditChain(context.Background()); err != nil || !res.OK {
		t.Fatalf("verify: %+v, %v", res, err)
	}
}

func TestAuditConfigRejectsShortHashKey(t *testing.T) {
	_, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		Audit: &theauth.AuditConfig{InputHashKey: []byte("short")},
	})
	if err == nil || !strings.Contains(err.Error(), "InputHashKey") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuditConfigRotationNeedsCapableStorage(t *testing.T) {
	_, err := theauth.New(theauth.Config{
		Storage: noChainStore{memory.New()}, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		Audit: &theauth.AuditConfig{PseudonymRotation: &theauth.PseudonymRotation{PeriodDays: 1}},
	})
	if err != nil {
		t.Fatalf("embedding keeps the methods, so this backend is capable: %v", err)
	}
	_, err = theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		Audit: &theauth.AuditConfig{PseudonymRotation: &theauth.PseudonymRotation{PeriodDays: 0}},
	})
	if err == nil {
		t.Fatal("PeriodDays 0 accepted")
	}
}

func TestShredAuditPseudonymsWithoutRotation(t *testing.T) {
	a := provenanceAuth(t, theauth.AuditConfig{})
	defer a.Close()
	if got, err := a.ShredAuditPseudonyms(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("no rotation configured: %v, %v", got, err)
	}
}

func TestAdminAuditProvenanceFilter(t *testing.T) {
	fx := newAdminFixture(t)
	ctx := t.Context()
	var h audit.InputHasher
	orgID := fx.orgID
	for i, content := range []string{"alpha", "beta"} {
		err := fx.store.InsertAuditEvents(ctx, []theauth.AuditEvent{{
			ID: internalulid.New(), OrganizationID: &orgID, Action: "agent.authorize", CreatedAt: time.Now().Add(time.Duration(i) * time.Millisecond),
			InputProvenance: audit.BuildInputProvenance(h, []audit.InputSource{{Kind: audit.InputToolOutput, Content: content}}),
		}})
		if err != nil {
			t.Fatal(err)
		}
	}
	base := "/admin/v1/organizations/" + orgID.String() + "/audit"
	resp, body := fx.do(t, "GET", base+"?provenance_kind=tool_output&provenance_hash="+h.Hash("alpha"), fx.ownerTok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var got struct {
		Events []theauth.AuditEvent `json:"events"`
	}
	if err := json.Unmarshal(body, &got); err != nil || len(got.Events) != 1 {
		t.Fatalf("events = %d, %v, body=%s", len(got.Events), err, body)
	}
	resp, body = fx.do(t, "GET", base+"?provenance_kind=nope", fx.ownerTok, nil)
	if resp.StatusCode != 400 || !strings.Contains(string(body), "validation.invalid") {
		t.Fatalf("bad kind: status=%d body=%s", resp.StatusCode, body)
	}
	resp, body = fx.do(t, "GET", base+"?provenance_hash=XYZ", fx.ownerTok, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("bad hash: status=%d body=%s", resp.StatusCode, body)
	}
}
