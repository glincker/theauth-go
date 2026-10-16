package shrink

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

// DistinctCap bounds the distinct pairs kept in DeniedNoGrant and Uncovered, so
// memory stays bounded however large the window is.
const DistinctCap = 5000

type useState struct {
	count       int
	first, last time.Time
	chains      map[string]struct{}
}

// UsageAccumulator is the pure core behind AnalyzeUsage. Feed it rows in any
// order, then call Finish. A row is attributed to the first grant that matches
// it, the order the engine tries them in.
type UsageAccumulator struct {
	agentID   string
	since     time.Time
	until     time.Time
	grants    []Grant
	perms     []Permission
	used      map[int]*useState
	attempted map[int]struct{}
	denied    map[Pair]struct{}
	uncovered map[Pair]int
	ev        Evidence
}

// NewUsageAccumulator starts an analysis of agentID over grants.
func NewUsageAccumulator(agentID string, grants []Grant, since, until time.Time) *UsageAccumulator {
	perms := make([]Permission, len(grants))
	for i, g := range grants {
		perms[i] = g.Permission
	}
	return &UsageAccumulator{
		agentID: agentID, since: since, until: until, grants: grants, perms: perms,
		used: map[int]*useState{}, attempted: map[int]struct{}{},
		denied: map[Pair]struct{}{}, uncovered: map[Pair]int{},
	}
}

// Add classifies and attributes one row.
func (u *UsageAccumulator) Add(r DecisionRow) {
	u.ev.RowsScanned++
	switch Classify(r) {
	case ClassInternal:
		u.ev.InternalRows++
	case ClassDenyNoGrant:
		u.ev.NoGrantDenials++
		p := Pair{r.Action, r.Resource}
		if _, ok := u.denied[p]; !ok && len(u.denied) < DistinctCap {
			u.denied[p] = struct{}{}
		}
	case ClassDenyOther:
		// Denied for another cause: the grant was exercised, so it is not proof of non-use.
		u.ev.OtherDenials++
		if i := firstMatch(u.perms, r.Action, r.Resource); i >= 0 {
			u.attempted[i] = struct{}{}
		}
	case ClassAllow:
		u.ev.AllowedRows++
		i := firstMatch(u.perms, r.Action, r.Resource)
		if i < 0 {
			u.ev.UncoveredAllows++
			p := Pair{r.Action, r.Resource}
			if _, ok := u.uncovered[p]; ok || len(u.uncovered) < DistinctCap {
				u.uncovered[p]++
			}
			return
		}
		s := u.used[i]
		if s == nil {
			s = &useState{first: r.Timestamp, last: r.Timestamp, chains: map[string]struct{}{}}
			u.used[i] = s
		}
		s.count++
		if r.Timestamp.Before(s.first) {
			s.first = r.Timestamp
		}
		if r.Timestamp.After(s.last) {
			s.last = r.Timestamp
		}
		src := u.grants[i].Source
		if src.ChainID != "" {
			s.chains[src.ChainID] = struct{}{}
		}
		if src.Kind == SourceDelegation {
			for _, id := range r.DelegationChain {
				s.chains[id] = struct{}{}
			}
		}
	}
}

func comparePair(a, b Pair) int {
	return cmp.Or(strings.Compare(a.Resource, b.Resource), strings.Compare(a.Action, b.Action))
}

// Finish returns the analysis. The accumulator can keep taking rows afterwards.
func (u *UsageAccumulator) Finish() *UsageAnalysis {
	a := &UsageAnalysis{
		AgentID: u.agentID, Since: u.since, Until: u.until,
		Grants: u.grants, Evidence: u.ev,
	}
	for i, g := range u.grants {
		if s, ok := u.used[i]; ok {
			via := make([]string, 0, len(s.chains))
			for id := range s.chains {
				via = append(via, id)
			}
			slices.Sort(via)
			a.Used = append(a.Used, UsedPermission{
				Permission: g.Permission, Count: s.count, FirstSeen: s.first, LastSeen: s.last, Via: via,
			})
		} else if _, ok := u.attempted[i]; ok {
			a.AttemptedOnly = append(a.AttemptedOnly, g.Permission)
		} else {
			a.Unused = append(a.Unused, g.Permission)
		}
	}
	for p := range u.denied {
		a.DeniedNoGrant = append(a.DeniedNoGrant, p)
	}
	slices.SortFunc(a.DeniedNoGrant, comparePair)
	for p, n := range u.uncovered {
		a.Uncovered = append(a.Uncovered, UncoveredAllow{Pair: p, Count: n})
	}
	slices.SortFunc(a.Uncovered, func(x, y UncoveredAllow) int { return comparePair(x.Pair, y.Pair) })
	return a
}

// AnalyzeUsage compares what an agent is granted with what it actually did.
// Rows are read in pages, so a long window does not load into memory at once.
//
// Grants are split to one action each, so "read and write on X" shows up as
// two entries and only the unused half is flagged. Only allowed rows count as
// use. A denial for another cause (rate limit, time window, approval, revoked
// agent) never counts as evidence that a grant is unused.
func AnalyzeUsage(ctx context.Context, grants GrantSource, rows RowSource, agentID string, opts AnalyzeOptions) (*UsageAnalysis, error) {
	gs, err := grants.Grants(ctx, agentID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("shrink: load grants for agent %s: %w", agentID, err)
	}
	acc := NewUsageAccumulator(agentID, gs, opts.Since, opts.Until)
	q := RowQuery{AgentID: agentID, Since: opts.Since, Until: opts.Until}
	if err := walk(ctx, rows, q, opts.PageSize, acc.Add); err != nil {
		return nil, err
	}
	return acc.Finish(), nil
}
