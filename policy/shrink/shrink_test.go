package shrink

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/policy"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func perm(action, resource string) Permission { return Permission{Action: action, Resource: resource} }

func own(action, resource string) Grant {
	return Grant{Permission: perm(action, resource), Source: Origin{Kind: SourceOwn}}
}

func row(id, action, resource, result, reason string, min int) DecisionRow {
	return DecisionRow{ID: id, Action: action, Resource: resource, Result: result, Reason: reason, Timestamp: t0.Add(time.Duration(min) * time.Minute)}
}

func allow(id, action, resource string, min int) DecisionRow {
	return row(id, action, resource, ResultAllowed, "", min)
}

const noGrant = "no matching allow statement (default deny)"

func analyze(t *testing.T, grants []Grant, rows []DecisionRow) *UsageAnalysis {
	t.Helper()
	a, err := AnalyzeUsage(context.Background(), StaticGrants(grants), MemoryRows(rows), "agent", AnalyzeOptions{PageSize: 3})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		row  DecisionRow
		want RowClass
	}{
		{"allowed", row("1", "read", "x", ResultAllowed, "", 0), ClassAllow},
		{"default deny", row("2", "read", "x", ResultDenied, noGrant, 0), ClassDenyNoGrant},
		{"legacy reason", row("3", "read", "x", ResultDenied, "No permission grants agent a access", 0), ClassDenyNoGrant},
		{"code reason", row("4", "read", "x", ResultDenied, "POLICY_NO_MATCHING_PERMISSION", 0), ClassDenyNoGrant},
		{"explicit deny is other", row("5", "read", "x", ResultDenied, "explicit deny", 0), ClassDenyOther},
		{"denied without reason", row("6", "read", "x", ResultDenied, "", 0), ClassDenyOther},
		{"rate limited", row("7", "read", "x", ResultRateLimited, noGrant, 0), ClassDenyOther},
		{"escalated", row("8", "read", "x", ResultEscalated, "", 0), ClassDenyOther},
		{"audit prefix", row("9", "audit.events_dropped", "x", ResultAllowed, "", 0), ClassInternal},
		{"cascade", row("10", "agent.cascade.revoked", "x", ResultAllowed, "", 0), ClassInternal},
		{"delegation", row("11", "delegation.granted", "x", ResultAllowed, "", 0), ClassInternal},
		{"approval", row("12", "approval.decided", "x", ResultDenied, noGrant, 0), ClassInternal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.row); got != tc.want {
				t.Fatalf("Classify = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAnalyzeUsage(t *testing.T) {
	grants := []Grant{
		own("read", "mcp:github:*"),
		own("read", "mcp:github:issues"),
		own("write", "mcp:github:issues"),
		own("send", "tool:mail"),
		own("query", "tool:db"),
		own("delete", "tool:db"),
	}
	rows := []DecisionRow{
		allow("1", "read", "mcp:github:repos", 1),
		allow("2", "read", "mcp:github:issues", 3), // first match is the wildcard, not the narrow grant
		allow("3", "read", "mcp:github:pulls", 2),
		allow("4", "query", "tool:db", 5),
		row("5", "send", "tool:mail", ResultRateLimited, "rate limited", 6),
		row("6", "delete", "tool:db", ResultDenied, noGrant, 7),
		row("7", "write", "tool:billing", ResultDenied, noGrant, 8),
		allow("8", "export", "tool:db", 9), // no grant covers an allow
		allow("9", "read", "x", 10),
		row("10", "agent.cascade.revoked", "agent", ResultAllowed, "", 11),
	}
	rows[8].Action = "audit.checkpoint"
	a := analyze(t, grants, rows)

	if len(a.Used) != 2 {
		t.Fatalf("used = %+v", a.Used)
	}
	u := a.Used[0]
	if u.Permission.Resource != "mcp:github:*" || u.Count != 3 || !u.FirstSeen.Equal(t0.Add(time.Minute)) || !u.LastSeen.Equal(t0.Add(3*time.Minute)) {
		t.Fatalf("wildcard usage = %+v", u)
	}
	wantUnused := []Permission{perm("read", "mcp:github:issues"), perm("write", "mcp:github:issues"), perm("delete", "tool:db")}
	if !slices.EqualFunc(a.Unused, wantUnused, func(x, y Permission) bool { return x.Action == y.Action && x.Resource == y.Resource }) {
		t.Fatalf("unused = %+v", a.Unused)
	}
	if len(a.AttemptedOnly) != 1 || a.AttemptedOnly[0].Resource != "tool:mail" {
		t.Fatalf("attempted = %+v", a.AttemptedOnly)
	}
	if len(a.DeniedNoGrant) != 2 || a.DeniedNoGrant[1] != (Pair{"delete", "tool:db"}) {
		t.Fatalf("denied = %+v", a.DeniedNoGrant)
	}
	if len(a.Uncovered) != 1 || a.Uncovered[0].Action != "export" || a.Uncovered[0].Count != 1 {
		t.Fatalf("uncovered = %+v", a.Uncovered)
	}
	want := Evidence{RowsScanned: 10, AllowedRows: 5, NoGrantDenials: 2, OtherDenials: 1, InternalRows: 2, UncoveredAllows: 1}
	if a.Evidence != want {
		t.Fatalf("evidence = %+v, want %+v", a.Evidence, want)
	}
}

func TestAnalyzeNoRows(t *testing.T) {
	a := analyze(t, []Grant{own("read", "a"), own("write", "a")}, nil)
	if len(a.Unused) != 2 || len(a.Used) != 0 || a.Evidence.RowsScanned != 0 {
		t.Fatalf("analysis = %+v", a)
	}
}

func TestAnalyzeDelegationVia(t *testing.T) {
	grants := []Grant{
		own("read", "doc:own"),
		{Permission: perm("read", "doc:shared"), Source: Origin{Kind: SourceDelegation, ChainID: "g1"}},
	}
	r := allow("1", "read", "doc:shared", 1)
	r.DelegationChain = []string{"g0", "g1"}
	a := analyze(t, grants, []DecisionRow{r})
	if len(a.Used) != 1 || !slices.Equal(a.Used[0].Via, []string{"g0", "g1"}) {
		t.Fatalf("used = %+v", a.Used)
	}
}

func TestPagingNeverSkipsSharedTimestamps(t *testing.T) {
	var rows []DecisionRow
	for i := 0; i < 25; i++ {
		rows = append(rows, allow(fmt.Sprintf("r%02d", i), "read", "doc:a", i/5)) // five rows per timestamp
	}
	for _, size := range []int{1, 2, 4, 5, 7, 25, 100} {
		a, err := AnalyzeUsage(context.Background(), StaticGrants{own("read", "doc:a")}, MemoryRows(rows), "agent", AnalyzeOptions{PageSize: size})
		if err != nil {
			t.Fatal(err)
		}
		if a.Used[0].Count != 25 || a.Evidence.RowsScanned != 25 {
			t.Fatalf("page size %d: count %d scanned %d", size, a.Used[0].Count, a.Evidence.RowsScanned)
		}
	}
}

func TestWindow(t *testing.T) {
	rows := []DecisionRow{allow("1", "read", "a", 0), allow("2", "read", "a", 10), allow("3", "read", "a", 20)}
	a, err := AnalyzeUsage(context.Background(), StaticGrants{own("read", "a")}, MemoryRows(rows), "agent",
		AnalyzeOptions{Since: t0.Add(5 * time.Minute), Until: t0.Add(15 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if a.Used[0].Count != 1 {
		t.Fatalf("count = %d", a.Used[0].Count)
	}
}

type stuckRows struct{}

func (stuckRows) Rows(_ context.Context, q RowQuery) ([]DecisionRow, string, error) {
	return nil, "same", nil
}

type failRows struct{ err error }

func (f failRows) Rows(context.Context, RowQuery) ([]DecisionRow, string, error) {
	return nil, "", f.err
}

func TestReadErrors(t *testing.T) {
	ctx := context.Background()
	_, err := AnalyzeUsage(ctx, StaticGrants{}, stuckRows{}, "a", AnalyzeOptions{})
	if !errors.Is(err, ErrCursorStuck) {
		t.Fatalf("err = %v", err)
	}
	boom := errors.New("boom")
	_, err = PreviewPolicyChange(ctx, failRows{boom}, "a", nil, PreviewOptions{})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = AnalyzeUsage(cctx, StaticGrants{}, MemoryRows{}, "a", AnalyzeOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func suggestFor(t *testing.T, grants []Grant, rows []DecisionRow, opts Options) (Suggestion, *UsageAnalysis) {
	t.Helper()
	a := analyze(t, grants, rows)
	return SuggestShrink(a, opts), a
}

func repeat(action, resource string, n int) []DecisionRow {
	var out []DecisionRow
	for i := 0; i < n; i++ {
		out = append(out, allow(fmt.Sprintf("%s-%s-%d", action, resource, i), action, resource, i))
	}
	return out
}

func TestSuggestShrink(t *testing.T) {
	siblings := []Grant{own("read", "mcp:github:issues"), own("read", "mcp:github:pulls"), own("read", "mcp:github:repos")}
	wide := append(slices.Clone(siblings), own("read", "mcp:github:*"))
	use := func() []DecisionRow {
		var r []DecisionRow
		for _, s := range []string{"issues", "pulls", "repos"} {
			r = append(r, repeat("read", "mcp:github:"+s, 2)...)
		}
		return r
	}
	tests := []struct {
		name     string
		grants   []Grant
		rows     []DecisionRow
		opts     Options
		wantKeep []string
		wantRew  int
	}{
		{"min observations drops rare", []Grant{own("read", "a"), own("read", "b")},
			append(repeat("read", "a", 5), repeat("read", "b", 2)...), Options{MinObservations: 3}, []string{"read a"}, 0},
		{"no generalize by default", siblings, use(), Options{}, []string{"read mcp:github:issues", "read mcp:github:pulls", "read mcp:github:repos"}, 0},
		{"generalize within existing grant", wide, use(), Options{Generalize: true}, []string{"read mcp:github:*"}, 1},
		{"wide grant listed first takes the credit", append([]Grant{own("read", "mcp:github:*")}, siblings...), use(), Options{Generalize: true}, []string{"read mcp:github:*"}, 0},
		{"no covering grant, no merge", siblings, use(), Options{Generalize: true},
			[]string{"read mcp:github:issues", "read mcp:github:pulls", "read mcp:github:repos"}, 0},
		{"denied no-grant blocks merge", []Grant{own("read", "mcp:github:issues"), own("read", "mcp:github:pulls"), own("read", "mcp:github:repos"), own("read", "mcp:*")},
			append(use(), row("d", "read", "mcp:github:secrets", ResultDenied, noGrant, 99)), Options{Generalize: true},
			[]string{"read mcp:github:issues", "read mcp:github:pulls", "read mcp:github:repos"}, 0},
		{"needs generalizeMin siblings", wide, use(), Options{Generalize: true, GeneralizeMin: 4}, []string{"read mcp:github:issues", "read mcp:github:pulls", "read mcp:github:repos"}, 0},
		{"attempted only is kept", []Grant{own("send", "tool:mail"), own("read", "a")},
			append(repeat("read", "a", 1), row("r", "send", "tool:mail", ResultRateLimited, "rate", 5)), Options{}, []string{"send tool:mail", "read a"}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := suggestFor(t, tc.grants, tc.rows, tc.opts)
			var got []string
			for _, p := range s.Keep {
				got = append(got, p.Action+" "+p.Resource)
			}
			if !slices.Equal(got, tc.wantKeep) {
				t.Fatalf("keep = %v, want %v", got, tc.wantKeep)
			}
			if len(s.Rewrites) != tc.wantRew {
				t.Fatalf("rewrites = %+v", s.Rewrites)
			}
		})
	}
}

func TestSuggestDeterministic(t *testing.T) {
	grants := []Grant{own("read", "a:x"), own("read", "a:y"), own("read", "a:z"), own("read", "a:*")}
	rows := append(append(repeat("read", "a:x", 2), repeat("read", "a:y", 2)...), repeat("read", "a:z", 2)...)
	a := analyze(t, grants, rows)
	first := SuggestShrink(a, Options{Generalize: true})
	for i := 0; i < 20; i++ {
		got := SuggestShrink(a, Options{Generalize: true})
		if fmt.Sprint(got) != fmt.Sprint(first) {
			t.Fatalf("run %d differs", i)
		}
	}
}

func TestSuggestCarriesConditions(t *testing.T) {
	c := []policy.Condition{{Op: policy.OpIPCIDR, Key: "ip", Values: []string{"10.0.0.0/8"}}}
	g := Grant{Permission: Permission{Action: "read", Resource: "a", Conditions: c}, Source: Origin{Kind: SourceOwn}}
	s, _ := suggestFor(t, []Grant{g}, repeat("read", "a", 1), Options{})
	if len(s.Keep) != 1 || len(s.Keep[0].Conditions) != 1 || s.Keep[0].Conditions[0].Op != policy.OpIPCIDR {
		t.Fatalf("keep = %+v", s.Keep)
	}
}

func TestVerifyShrink(t *testing.T) {
	proposed := []Permission{perm("read", "a:*")}
	rows := []DecisionRow{
		allow("1", "read", "a:1", 1),
		allow("2", "write", "a:1", 2),
		row("3", "read", "a:2", ResultDenied, noGrant, 3),
		row("4", "write", "b", ResultDenied, noGrant, 4),
		row("5", "read", "a:3", ResultRateLimited, "rl", 5),
		allow("6", "audit.x", "a:1", 6),
	}
	r := VerifyShrink(slices.Values(rows), proposed, VerifyOptions{})
	if r.ReplayedAllows != 2 || r.StillAllowed != 1 || r.NewlyDeniedCount != 1 || r.NewlyDenied[0].ID != "2" ||
		r.WouldAlsoAllowCount != 1 || r.WouldAlsoAllow[0].ID != "3" || r.IgnoredRows != 2 || r.PerPermission[0].Allows != 1 || r.Truncated {
		t.Fatalf("report = %+v", r)
	}
}

func TestVerifyCapsExamples(t *testing.T) {
	var rows []DecisionRow
	for i := 0; i < 10; i++ {
		rows = append(rows, allow(fmt.Sprint(i), "read", "x", i))
	}
	r := VerifyShrink(slices.Values(rows), nil, VerifyOptions{MaxExamples: 3})
	if r.NewlyDeniedCount != 10 || len(r.NewlyDenied) != 3 || !r.Truncated {
		t.Fatalf("report = %+v", r)
	}
}

func TestPreviewWidening(t *testing.T) {
	rows := []DecisionRow{allow("1", "read", "a", 1), row("2", "write", "a", ResultDenied, noGrant, 2)}
	p, err := PreviewPolicyChange(context.Background(), MemoryRows(rows), "agent",
		[]Permission{perm("read", "a"), perm("write", "a")}, PreviewOptions{PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if p.RowsScanned != 2 || p.WouldAlsoAllowCount != 1 || p.NewlyDeniedCount != 0 || p.AgentID != "agent" {
		t.Fatalf("preview = %+v", p)
	}
}

func TestCovers(t *testing.T) {
	tests := []struct {
		outer, inner Permission
		want         bool
	}{
		{perm("read", "a:*"), perm("read", "a:b"), true},
		{perm("read", "a:b"), perm("read", "a:*"), false},
		{perm("read", "a:*"), perm("read", "a:*"), true},
		{perm("*", "a:*"), perm("write", "a:b"), true},
		{perm("read", "a:*"), perm("write", "a:b"), false},
		{perm("read", "a:b:*"), perm("read", "a:*"), false},
	}
	for _, tc := range tests {
		if got := Covers(tc.outer, tc.inner); got != tc.want {
			t.Errorf("Covers(%v, %v) = %v, want %v", tc.outer, tc.inner, got, tc.want)
		}
	}
}

func TestPolicyGrantsAndStatements(t *testing.T) {
	doc, err := policy.Parse([]byte(`{"version":"1","id":"p1","statements":[
	 {"effect":"allow","actions":["read","write"],"resources":["a","b"]},
	 {"effect":"deny","actions":["*"],"resources":["secret"]},
	 {"effect":"allow","actions":["read"],"resources":["a"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	gs := PolicyGrants([]*policy.Policy{doc, nil})
	if len(gs) != 4 {
		t.Fatalf("grants = %+v", gs)
	}
	if gs[0].Source.PolicyID != "p1" || gs[0].Source.StatementID != "statement-0" {
		t.Fatalf("source = %+v", gs[0].Source)
	}
	perms := make([]Permission, len(gs))
	for i, g := range gs {
		perms[i] = g.Permission
	}
	st := Statements(perms)
	if len(st) != 2 || !slices.Equal(st[0].Actions, []string{"read", "write"}) || st[0].Resources[0] != "a" {
		t.Fatalf("statements = %+v", st)
	}
	if err := (&policy.Policy{Version: policy.Version, Statements: st}).Validate(); err != nil {
		t.Fatal(err)
	}
}

// TestProperty draws random grant sets and call logs, derives the logs from the
// grants the way an engine would, and checks that the suggestion reproduces
// every allow and admits nothing that was denied for lack of a grant.
func TestProperty(t *testing.T) {
	actions := []string{"read", "write", "delete", "*"}
	parents := []string{"mcp:github", "mcp:slack", "tool:db"}
	leaves := []string{"a", "b", "c", "d", "e", "*"}
	rewrites := 0
	for seed := int64(1); seed <= 150; seed++ {
		for _, gen := range []bool{false, true} {
			rng := rand.New(rand.NewSource(seed))
			var grants []Grant
			for i, n := 0, 3+rng.Intn(10); i < n; i++ {
				res := parents[rng.Intn(len(parents))] + ":" + leaves[rng.Intn(len(leaves))]
				if rng.Intn(8) == 0 {
					res = parents[rng.Intn(len(parents))][:3] + "*"
				}
				grants = append(grants, own(actions[rng.Intn(len(actions))], res))
			}
			if rng.Intn(2) == 0 {
				// Siblings first, then a covering wildcard, so merges are possible.
				p, act := parents[rng.Intn(len(parents))], actions[rng.Intn(3)]
				for _, l := range leaves[:3+rng.Intn(3)] {
					grants = append(grants, own(act, p+":"+l))
				}
				grants = append(grants, own(act, p+":*"))
			}
			perms := make([]Permission, len(grants))
			for i, g := range grants {
				perms[i] = g.Permission
			}
			var rows []DecisionRow
			for i, n := 0, rng.Intn(120); i < n; i++ {
				act := actions[rng.Intn(3)]
				res := parents[rng.Intn(len(parents))] + ":" + leaves[rng.Intn(5)]
				r := row(fmt.Sprintf("r%03d", i), act, res, ResultAllowed, "", rng.Intn(30))
				switch hit := firstMatch(perms, act, res) >= 0; {
				case !hit:
					r.Result, r.Reason = ResultDenied, noGrant
				case rng.Intn(6) == 0:
					r.Result, r.Reason = ResultRateLimited, "rate limited"
				}
				rows = append(rows, r)
			}
			a, err := AnalyzeUsage(context.Background(), StaticGrants(grants), MemoryRows(rows), "agent", AnalyzeOptions{PageSize: 1 + rng.Intn(9)})
			if err != nil {
				t.Fatal(err)
			}
			s := SuggestShrink(a, Options{Generalize: gen, MinObservations: 1})
			rewrites += len(s.Rewrites)
			rep := VerifyShrink(slices.Values(rows), s.Keep, VerifyOptions{})
			if rep.NewlyDeniedCount != 0 || rep.WouldAlsoAllowCount != 0 {
				t.Fatalf("seed %d generalize=%v: denied %d allowed %d keep=%v grants=%v", seed, gen, rep.NewlyDeniedCount, rep.WouldAlsoAllowCount, s.Keep, perms)
			}
			// Never wider than today: every kept permission is covered by an existing grant.
			for _, k := range s.Keep {
				if !slices.ContainsFunc(perms, func(g Permission) bool { return Covers(g, k) }) {
					t.Fatalf("seed %d generalize=%v: %v is wider than any grant", seed, gen, k)
				}
			}
		}
	}
	if rewrites == 0 {
		t.Fatal("property test never exercised a generalization")
	}
}
