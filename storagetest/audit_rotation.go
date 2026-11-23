package storagetest

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/audit"
)

// AuditRotationSuiteStorage is the storage RunAuditRotation needs: a chained backend that can
// rotate audit pseudonyms (theauth.AuditPseudonymRotator).
type AuditRotationSuiteStorage interface {
	AuditChainSuiteStorage
	SetAuditPseudonymRotation(r audit.Rotation) error
	ShredAuditPseudonyms(ctx context.Context) ([]int64, error)
}

// RunAuditRotation runs the rotating pseudonym contract. It turns rotation on for the store and
// leaves it on, so run it last on a store you share with other suites. It checks that rows of
// several periods verify together with rows written before rotation, that shredding old periods
// keeps the chain verifying, and that erasing a user still verifies.
func RunAuditRotation(t *testing.T, store AuditRotationSuiteStorage) {
	t.Helper()
	t.Run("AuditRotation", func(t *testing.T) {
		t.Run("MixedPeriodsVerify", func(t *testing.T) { rotationMixed(t, store) })
		t.Run("ShredKeepsChainValid", func(t *testing.T) { rotationShred(t, store) })
		t.Run("SurvivesUserErasure", func(t *testing.T) { rotationErasure(t, store) })
		t.Run("RejectsBadPeriod", func(t *testing.T) {
			if err := store.SetAuditPseudonymRotation(audit.Rotation{PeriodDays: 0}); err == nil {
				t.Fatal("PeriodDays 0 accepted")
			}
		})
	})
}

func rotationInsert(t *testing.T, store AuditChainSuiteStorage, action string, at time.Time, subject string) {
	t.Helper()
	if err := store.InsertAuditEvents(context.Background(), []theauth.AuditEvent{{
		ID: newID(), Action: action, CreatedAt: at, SubjectID: subject, ActorID: "agent_rot",
	}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

func rotationMixed(t *testing.T, store AuditRotationSuiteStorage) {
	// A row written before rotation is on keeps its stable pseudonym.
	now := time.Now()
	rotationInsert(t, store, "storagetest.rot.before", now, "subject_stable")
	before := mustVerify(t, store)
	if err := store.SetAuditPseudonymRotation(audit.Rotation{PeriodDays: 1, RetainPeriods: 30}); err != nil {
		t.Fatalf("SetAuditPseudonymRotation: %v", err)
	}
	for i := 0; i < 3; i++ {
		rotationInsert(t, store, "storagetest.rot.mixed", now.Add(-time.Duration(i)*24*time.Hour), "subject_rot")
	}
	after := mustVerify(t, store)
	if after.Checked != before.Checked+3 {
		t.Fatalf("checked = %d, want %d", after.Checked, before.Checked+3)
	}
}

func rotationShred(t *testing.T, store AuditRotationSuiteStorage) {
	now := time.Now()
	if err := store.SetAuditPseudonymRotation(audit.Rotation{PeriodDays: 1, RetainPeriods: 1}); err != nil {
		t.Fatalf("SetAuditPseudonymRotation: %v", err)
	}
	// Rows 5 and 9 days old, written under their own period secrets, then the current period.
	rotationInsert(t, store, "storagetest.rot.shred", now.Add(-9*24*time.Hour), "subject_shred")
	rotationInsert(t, store, "storagetest.rot.shred", now.Add(-5*24*time.Hour), "subject_shred")
	rotationInsert(t, store, "storagetest.rot.shred", now, "subject_shred")
	if _, err := store.ShredAuditPseudonyms(context.Background()); err != nil {
		t.Fatalf("ShredAuditPseudonyms: %v", err)
	}
	// Nothing older than the retention window is left to shred, and the chain still verifies with
	// the raw ids on the shredded rows no longer checkable.
	again, err := store.ShredAuditPseudonyms(context.Background())
	if err != nil || len(again) != 0 {
		t.Fatalf("second shred = %v, %v; want nothing", again, err)
	}
	mustVerify(t, store)
}

func rotationErasure(t *testing.T, store AuditRotationSuiteStorage) {
	ctx := context.Background()
	if err := store.SetAuditPseudonymRotation(audit.Rotation{PeriodDays: 1, RetainPeriods: 30}); err != nil {
		t.Fatalf("SetAuditPseudonymRotation: %v", err)
	}
	u, err := store.CreateUser(ctx, theauth.User{ID: newID(), Email: "rot-erase@storagetest.example", CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for i := 0; i < 2; i++ {
		actor := u.ID
		if err := store.InsertAuditEvents(ctx, []theauth.AuditEvent{{
			ID: newID(), Action: "storagetest.rot.erase", CreatedAt: time.Now().Add(-time.Duration(i) * 24 * time.Hour),
			ActorUserID: &actor, SubjectID: u.ID.String(), ApproverID: u.ID.String(),
		}}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	before := mustVerify(t, store)
	if err := store.DeleteUserCascade(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUserCascade: %v", err)
	}
	after := mustVerify(t, store)
	if after.Checked != before.Checked || after.Erased != before.Erased+2 {
		t.Fatalf("after erasure = %+v, before = %+v", after, before)
	}
}
