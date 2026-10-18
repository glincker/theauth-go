package sqlite_test

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/audit"
)

func rotationStore(t *testing.T, r *audit.Rotation) (*sqlitestore.Store, *sql.DB) {
	t.Helper()
	db := openDB(t)
	if err := sqlitestore.Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := sqlitestore.New(db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if r != nil {
		if err := s.SetAuditPseudonymRotation(*r); err != nil {
			t.Fatalf("SetAuditPseudonymRotation: %v", err)
		}
	}
	return s, db
}

func insertSubject(t *testing.T, s *sqlitestore.Store, at time.Time, subject string) theauth.ULID {
	t.Helper()
	id := newID()
	if err := s.InsertAuditEvents(context.Background(), []theauth.AuditEvent{{
		ID: id, Action: "rot.test", CreatedAt: at, SubjectID: subject,
	}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return id
}

func pseudonymOf(t *testing.T, db *sql.DB, id theauth.ULID) string {
	t.Helper()
	var p string
	if err := db.QueryRow(`SELECT subject_pseudonym FROM theauth_audit_events WHERE id = ?`, id.String()).Scan(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRotationOneSubjectDiffersAcrossPeriods(t *testing.T) {
	t.Parallel()
	s, db := rotationStore(t, &audit.Rotation{PeriodDays: 1, RetainPeriods: 30})
	now := time.Now()
	a := insertSubject(t, s, now, "alice")
	b := insertSubject(t, s, now.Add(-48*time.Hour), "alice")
	c := insertSubject(t, s, now.Add(time.Second), "alice")
	pa, pb, pc := pseudonymOf(t, db, a), pseudonymOf(t, db, b), pseudonymOf(t, db, c)
	if pa == pb {
		t.Fatalf("same pseudonym in two periods: %s", pa)
	}
	if pa != pc {
		t.Fatalf("same subject in one period differs: %s vs %s", pa, pc)
	}
	want := audit.PeriodOf(now, 1)
	if !strings.HasPrefix(pa, "r1:") || !strings.Contains(pa, ":"+itoa(want)+":") {
		t.Fatalf("pseudonym %q not tagged with period %d", pa, want)
	}
	res, err := s.VerifyAuditChain(context.Background())
	if err != nil || !res.OK || res.Checked != 3 {
		t.Fatalf("verify: %+v, %v", res, err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestRotationShredUnlinksButChainStaysValid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := rotationStore(t, &audit.Rotation{PeriodDays: 1, RetainPeriods: 1})
	now := time.Now()
	old := insertSubject(t, s, now.Add(-10*24*time.Hour), "alice")
	recent := insertSubject(t, s, now, "alice")

	// Writing the current period already swept the old period secret.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM theauth_audit_period_secrets`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("period secrets = %d, %v; want 1 (the old one shredded)", n, err)
	}
	res, err := s.VerifyAuditChain(ctx)
	if err != nil || !res.OK || res.Checked != 2 {
		t.Fatalf("verify after shred: %+v, %v", res, err)
	}

	// The cost of shredding: a raw id edited on a shredded row cannot be compared any more. The chain
	// hash does not cover raw ids, only pseudonyms.
	if _, err := db.Exec(`UPDATE theauth_audit_events SET subject_id = 'mallory' WHERE id = ?`, old.String()); err != nil {
		t.Fatal(err)
	}
	if res, _ := s.VerifyAuditChain(ctx); !res.OK {
		t.Fatalf("shredded period must skip the raw id check: %+v", res)
	}
	// Where the secret is still held the same edit is caught.
	if _, err := db.Exec(`UPDATE theauth_audit_events SET subject_id = 'mallory' WHERE id = ?`, recent.String()); err != nil {
		t.Fatal(err)
	}
	res, err = s.VerifyAuditChain(ctx)
	if err != nil || res.OK || res.FirstBreak == nil || res.FirstBreak.Reason != "pseudonym_mismatch" {
		t.Fatalf("tampered raw id on a held period: %+v, %v", res, err)
	}
}

func TestRotationManualShred(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := rotationStore(t, &audit.Rotation{PeriodDays: 1, RetainPeriods: 30})
	now := time.Now()
	insertSubject(t, s, now.Add(-9*24*time.Hour), "alice")
	insertSubject(t, s, now.Add(-7*24*time.Hour), "alice")
	insertSubject(t, s, now, "alice")
	// All three periods fit the 30 period window, so nothing was shredded on write. Tighten the
	// window and shred on demand.
	if err := s.SetAuditPseudonymRotation(audit.Rotation{PeriodDays: 1, RetainPeriods: 5}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ShredAuditPseudonyms(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("shredded %v, %v; want the two periods older than 5 days", got, err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM theauth_audit_period_secrets`).Scan(&n)
	if n != 1 {
		t.Fatalf("secrets left = %d", n)
	}
	if res, err := s.VerifyAuditChain(ctx); err != nil || !res.OK {
		t.Fatalf("verify: %+v, %v", res, err)
	}
}

// Rows written before rotation keep their plain pseudonym and verify next to rotated ones, and
// turning rotation on does not touch them.
func TestRotationLeavesStableRowsAlone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := rotationStore(t, nil)
	now := time.Now()
	stable := insertSubject(t, s, now, "alice")
	before := pseudonymOf(t, db, stable)
	if strings.HasPrefix(before, "r1:") || len(before) != 64 {
		t.Fatalf("stable pseudonym = %q", before)
	}
	if err := s.SetAuditPseudonymRotation(audit.Rotation{PeriodDays: 7}); err != nil {
		t.Fatal(err)
	}
	rot := insertSubject(t, s, now.Add(time.Second), "alice")
	if got := pseudonymOf(t, db, stable); got != before {
		t.Fatal("stable row rewritten")
	}
	if got := pseudonymOf(t, db, rot); got == before || !strings.HasPrefix(got, "r1:") {
		t.Fatalf("rotated pseudonym = %q", got)
	}
	if res, err := s.VerifyAuditChain(ctx); err != nil || !res.OK || res.Checked != 2 {
		t.Fatalf("verify: %+v, %v", res, err)
	}
}

func TestRotationRefusesBadPolicy(t *testing.T) {
	t.Parallel()
	s, _ := rotationStore(t, nil)
	if err := s.SetAuditPseudonymRotation(audit.Rotation{PeriodDays: 0}); err == nil {
		t.Fatal("PeriodDays 0 accepted")
	}
}

func TestProvenanceFilterOnLegacySchemaMatchesNothing(t *testing.T) {
	t.Parallel()
	s, _ := rotationStore(t, nil)
	_, _, err := s.QueryAuditEvents(context.Background(), theauth.AuditQuery{
		Provenance: &theauth.AuditProvenanceFilter{Kind: audit.InputAgent},
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
}
