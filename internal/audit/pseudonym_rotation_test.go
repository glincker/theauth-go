package audit

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// Computed independently with python3 hmac: secret bytes 0..31, period 20000, id user_1.
const wantRotatedVector = "r1:20000:1eca875828f50066752772c7ae6629674399800353664d1bb1a7ef3003166d0a"

func testSecret() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestRotatingPseudonymVector(t *testing.T) {
	t.Parallel()
	if got := RotatingPseudonym(testSecret(), 20000, "user_1"); got != wantRotatedVector {
		t.Fatalf("got %s, want %s", got, wantRotatedVector)
	}
	if RotatingPseudonym(testSecret(), 20000, "") != "" {
		t.Fatal("empty id must stay empty")
	}
}

func TestPseudonymPeriodParsing(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		want int64
		ok   bool
	}{
		{wantRotatedVector, 20000, true},
		{"r1:-5:abcd", -5, true},
		{"deadbeef", 0, false},
		{"r1:abc:ff", 0, false},
		{"r1:12", 0, false},
		{"", 0, false},
	} {
		got, ok := PseudonymPeriod(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%q: got %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestPeriodOf(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	epoch := time.Unix(0, 0).UTC()
	for _, tc := range []struct {
		at   time.Time
		days int
		want int64
	}{
		{epoch, 1, 0},
		{epoch.Add(day - time.Millisecond), 1, 0},
		{epoch.Add(day), 1, 1},
		{epoch.Add(30*day - time.Millisecond), 30, 0},
		{epoch.Add(30 * day), 30, 1},
		{epoch.Add(-time.Millisecond), 1, -1},
		{epoch.Add(-day), 1, -1},
		{epoch.Add(-day - time.Millisecond), 1, -2},
	} {
		if got := PeriodOf(tc.at, tc.days); got != tc.want {
			t.Errorf("PeriodOf(%v, %d) = %d, want %d", tc.at, tc.days, got, tc.want)
		}
	}
}

func TestRotationNormalize(t *testing.T) {
	t.Parallel()
	if _, err := (Rotation{PeriodDays: 0}).Normalize(); err == nil {
		t.Fatal("PeriodDays 0 accepted")
	}
	for _, tc := range []struct{ in, want int }{{0, 1}, {3, 3}, {-1, 0}} {
		r, err := (Rotation{PeriodDays: 7, RetainPeriods: tc.in}).Normalize()
		if err != nil || r.RetainPeriods != tc.want {
			t.Errorf("retain %d -> %d, %v; want %d", tc.in, r.RetainPeriods, err, tc.want)
		}
	}
}

func TestPseudonymKeysCheck(t *testing.T) {
	t.Parallel()
	stable := []byte("stable-secret-stable-secret-1234")
	period := testSecret()
	keys := PseudonymKeys{Stable: stable, Periods: map[int64][]byte{7: period}}
	rot := RotatingPseudonym(period, 7, "u")
	cases := []struct {
		name        string
		raw, pseudo string
		want        bool
	}{
		{"stable ok", "u", Pseudonym(stable, "u"), true},
		{"stable wrong id", "v", Pseudonym(stable, "u"), false},
		{"rotated ok", "u", rot, true},
		{"rotated wrong id", "v", rot, false},
		{"rotated, period shredded", "v", RotatingPseudonym(period, 8, "u"), true},
		{"rotated pseudonym never matches stable", "u", RotatingPseudonym(stable, 7, "u"), false},
		{"empty pseudonym with raw id", "u", "", false},
	}
	for _, tc := range cases {
		if got := keys.Check(tc.raw, tc.pseudo); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	if !(PseudonymKeys{}).Check("u", Pseudonym(stable, "u")) {
		t.Error("no stable key must skip the check, as before")
	}
}

func TestPseudonymizerFailsClosed(t *testing.T) {
	t.Parallel()
	p := Pseudonymizer{Stable: []byte("k"), Rotation: &Rotation{PeriodDays: 1, RetainPeriods: 1}}
	if _, err := p.Of(time.Now(), "u"); err == nil {
		t.Fatal("missing period secret must fail, not fall back to the stable pseudonym")
	}
	if got, err := p.Of(time.Now(), ""); err != nil || got != "" {
		t.Fatalf("empty id = %q, %v", got, err)
	}
}

type fakePeriods struct {
	secrets map[int64][]byte
	creates int
}

func (f *fakePeriods) GetOrCreate(_ context.Context, p int64) ([]byte, error) {
	if s, ok := f.secrets[p]; ok {
		return s, nil
	}
	s, _ := NewPeriodSecret()
	f.secrets[p] = s
	f.creates++
	return s, nil
}

func (f *fakePeriods) Periods(context.Context) ([]int64, error) {
	var out []int64
	for p := range f.secrets {
		out = append(out, p)
	}
	return out, nil
}

func (f *fakePeriods) Delete(_ context.Context, ps []int64) error {
	for _, p := range ps {
		delete(f.secrets, p)
	}
	return nil
}

func (f *fakePeriods) sorted() []int64 {
	out, _ := f.Periods(context.Background())
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func TestRotationStateResolveAndShred(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	day := 24 * time.Hour
	base := time.Unix(0, 0).UTC().Add(100 * day)
	st := &fakePeriods{secrets: map[int64][]byte{}}
	var rs RotationState

	// Off: the stable pseudonymizer, nothing created.
	ps, err := rs.Resolve(ctx, []byte("stable"), st, []time.Time{base})
	if err != nil || ps.Rotation != nil || st.creates != 0 {
		t.Fatalf("off: %+v, %v, creates %d", ps, err, st.creates)
	}
	if err := rs.Set(&Rotation{PeriodDays: 1, RetainPeriods: 1}); err != nil {
		t.Fatal(err)
	}
	// Three days of writes: periods 98..100 exist, none older than current-1 yet except 98.
	for i := 2; i >= 0; i-- {
		if _, err := rs.Resolve(ctx, nil, st, []time.Time{base.Add(-time.Duration(i) * day)}); err != nil {
			t.Fatal(err)
		}
	}
	// Writing day 100 swept everything below 99.
	if got := st.sorted(); len(got) != 2 || got[0] != 99 || got[1] != 100 {
		t.Fatalf("periods after sweep = %v, want [99 100]", got)
	}
	// A new period shreds the one that fell out of the window.
	if _, err := rs.Resolve(ctx, nil, st, []time.Time{base.Add(day)}); err != nil {
		t.Fatal(err)
	}
	if got := st.sorted(); len(got) != 2 || got[0] != 100 || got[1] != 101 {
		t.Fatalf("periods = %v, want [100 101]", got)
	}
	// The same period again changes nothing and reuses the secret.
	before := st.creates
	if _, err := rs.Resolve(ctx, nil, st, []time.Time{base.Add(day + time.Hour)}); err != nil || st.creates != before {
		t.Fatalf("same period created a secret: %v", err)
	}
	// Two pseudonyms of one subject in different periods differ.
	psA, _ := rs.Resolve(ctx, nil, st, []time.Time{base, base.Add(day)})
	a, _ := psA.Of(base, "u")
	b, _ := psA.Of(base.Add(day), "u")
	if a == b {
		t.Fatal("a subject has the same pseudonym in two periods")
	}
}

func TestShredStalePeriodsReturnsSortedPeriods(t *testing.T) {
	t.Parallel()
	st := &fakePeriods{secrets: map[int64][]byte{1: {1}, 5: {1}, 3: {1}, 9: {1}, 10: {1}}}
	got, err := ShredStalePeriods(context.Background(), st, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != 1 || got[1] != 3 || got[2] != 5 {
		t.Fatalf("shredded = %v, want [1 3 5]", got)
	}
}

type failingPeriods struct{ fakePeriods }

func (failingPeriods) GetOrCreate(context.Context, int64) ([]byte, error) {
	return nil, errors.New("db down")
}

func TestResolveSurfacesStoreErrors(t *testing.T) {
	t.Parallel()
	var rs RotationState
	_ = rs.Set(&Rotation{PeriodDays: 1})
	_, err := rs.Resolve(context.Background(), nil, &failingPeriods{}, []time.Time{time.Now()})
	if err == nil {
		t.Fatal("store failure must fail the write, not fall back to the stable pseudonym")
	}
}

// A chain mixing a stable row, rotated rows and a shredded period verifies, and edits to a raw id
// are caught wherever the key is still present.
func TestVerifyChainRowsKeysMixed(t *testing.T) {
	t.Parallel()
	stable := []byte("stable-secret-stable-secret-1234")
	sec := map[int64][]byte{0: []byte("another period secret 0123456789"), 1: testSecret()}
	now := time.Unix(0, 0).UTC().Add(36 * time.Hour)
	var head ChainHead
	var rows []ChainRow
	add := func(ps Pseudonymizer, at time.Time, subject string) {
		e := models.AuditEvent{ID: models.ULID{1}, Action: "a", CreatedAt: at, SubjectID: subject}
		e.ID[15] = byte(len(rows) + 1)
		ce, err := BuildChainEntryWith(e, ps, head)
		if err != nil {
			t.Fatal(err)
		}
		head = ChainHead{Seq: ce.Payload.Seq, Hash: ce.Hash}
		rows = append(rows, ChainRow{Payload: ce.Payload, Hash: ce.Hash, RawSubject: subject})
	}
	add(Pseudonymizer{Stable: stable}, now, "alice") // before rotation
	rot := &Rotation{PeriodDays: 1, RetainPeriods: 1}
	add(Pseudonymizer{Stable: stable, Rotation: rot, Periods: sec}, now.Add(-24*time.Hour), "alice") // period 0, secret not held
	ps := Pseudonymizer{Stable: stable, Rotation: rot, Periods: map[int64][]byte{1: sec[1]}}
	add(ps, now, "alice")
	add(ps, now, "bob")

	run := func(keys PseudonymKeys, rs []ChainRow) models.AuditChainResult {
		n := 0
		res, err := VerifyChainRowsKeys(func() (ChainRow, bool, error) {
			if n >= len(rs) {
				return ChainRow{}, false, nil
			}
			n++
			return rs[n-1], true, nil
		}, keys, 0)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	keys := PseudonymKeys{Stable: stable, Periods: map[int64][]byte{1: sec[1]}}
	if res := run(keys, rows); !res.OK || res.Checked != 4 {
		t.Fatalf("mixed chain: %+v break %+v", res, res.FirstBreak)
	}
	// Edit a raw id on a row whose period key is held: caught.
	tampered := append([]ChainRow(nil), rows...)
	tampered[3].RawSubject = "mallory"
	if res := run(keys, tampered); res.OK || res.FirstBreak.Reason != "pseudonym_mismatch" {
		t.Fatalf("tampered raw id not caught: %+v", res)
	}
	// Same edit on the stable row is caught under the stable key.
	tampered = append([]ChainRow(nil), rows...)
	tampered[0].RawSubject = "mallory"
	if res := run(keys, tampered); res.OK || res.FirstBreak.Reason != "pseudonym_mismatch" {
		t.Fatalf("tampered stable row not caught: %+v", res)
	}
	// Period 0 was never given to the verifier (shredded): the same edit is not detectable there.
	// This is the documented cost of shredding.
	tampered = append([]ChainRow(nil), rows...)
	tampered[1].RawSubject = "mallory"
	if res := run(keys, tampered); !res.OK {
		t.Fatalf("shredded period must skip the raw id check: %+v", res)
	}
	// Editing a stored pseudonym breaks the chain hash whether or not the key is held.
	tampered = append([]ChainRow(nil), rows...)
	tampered[1].Payload.SubjectPseudo = RotatingPseudonym(sec[1], 1, "alice")
	if res := run(keys, tampered); res.OK || res.FirstBreak.Reason != "hash_mismatch" {
		t.Fatalf("edited pseudonym not caught: %+v", res)
	}
	// An erased row (raw id gone) still verifies through its pseudonym.
	erased := append([]ChainRow(nil), rows...)
	erased[2].RawSubject = ""
	if res := run(keys, erased); !res.OK || res.Erased != 1 {
		t.Fatalf("erased row: %+v", res)
	}
}

// Stable rows hash exactly as before: the golden vectors in chain_vectors_test.go cover that, and
// this pins that the default Pseudonymizer reproduces BuildChainEntry.
func TestBuildChainEntryWithStableMatchesBuildChainEntry(t *testing.T) {
	t.Parallel()
	secret := []byte("stable-secret-stable-secret-1234")
	e := models.AuditEvent{ID: models.ULID{9}, Action: "a", CreatedAt: time.Unix(1700000000, 0), SubjectID: "s", ActorID: "a", ApproverID: "p"}
	a, err := BuildChainEntry(e, secret, ChainHead{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildChainEntryWith(e, Pseudonymizer{Stable: secret}, ChainHead{})
	if err != nil || a.Hash != b.Hash {
		t.Fatalf("%v: %s vs %s", err, a.Hash, b.Hash)
	}
}
