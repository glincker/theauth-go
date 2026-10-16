package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

func TestAuditChainSurvivesUserErasure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := chainStore(t)
	u := mkUser(t, s, "erase@example.com")
	other := mkUser(t, s, "keep@example.com")
	uid := u.ID
	for i, actor := range []theauth.ULID{u.ID, other.ID, u.ID} {
		id := actor
		if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
			ID: newID(), Action: "agent.authorize", CreatedAt: time.Now(), ActorUserID: &id,
			SubjectID: u.ID.String(), ActorID: "agent_1", ApproverID: u.ID.String(), Metadata: map[string]any{"i": i},
		}}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	before, err := s.VerifyAuditChain(ctx)
	if err != nil || !before.OK || before.Checked != 3 || before.Erased != 0 {
		t.Fatalf("before erasure = %+v, %v", before, err)
	}
	var hashesBefore []string
	evs, _, _ := s.QueryAuditEvents(ctx, theauth.AuditQuery{Limit: 10})
	for _, e := range evs {
		hashesBefore = append(hashesBefore, e.Hash)
	}

	if err := s.DeleteUserCascade(ctx, uid); err != nil {
		t.Fatalf("DeleteUserCascade: %v", err)
	}

	after, err := s.VerifyAuditChain(ctx)
	if err != nil || !after.OK || after.Checked != 3 || after.Erased != 3 {
		t.Fatalf("after erasure = %+v, %v (break %+v)", after, err, after.FirstBreak)
	}
	evs, _, _ = s.QueryAuditEvents(ctx, theauth.AuditQuery{Limit: 10})
	for i, e := range evs {
		if e.Hash != hashesBefore[i] {
			t.Fatalf("hash changed by erasure for %s", e.ID)
		}
		if e.ActorUserID != nil && *e.ActorUserID == uid {
			t.Fatalf("raw actor id survived erasure")
		}
		if e.SubjectID == uid.String() || e.ApproverID == uid.String() {
			t.Fatalf("raw subject/approver id survived erasure: %+v", e)
		}
	}
}

func TestAuditChainDetectsRawIDEditViaPseudonym(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, exec := chainStore(t)
	id := newID()
	if err := s.InsertAuditEvents(ctx, []theauth.AuditEvent{{
		ID: id, Action: "a", CreatedAt: time.Now(), SubjectID: "user_1",
	}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Changing the raw id leaves the hashed pseudonym alone, so only the
	// pseudonym consistency check can catch it.
	exec(`UPDATE theauth_audit_events SET subject_id = 'user_2' WHERE id = ?`, id.String())
	res, err := s.VerifyAuditChain(ctx)
	if err != nil || res.OK || res.FirstBreak == nil || res.FirstBreak.Reason != "pseudonym_mismatch" {
		t.Fatalf("raw edit not detected: %+v, %v", res, err)
	}
}
