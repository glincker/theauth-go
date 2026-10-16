package shrink

import (
	"context"
	"fmt"
	"iter"
)

// DefaultMaxExamples is the most rows listed in each example list.
const DefaultMaxExamples = 1000

func ref(r DecisionRow) RowRef {
	return RowRef{ID: r.ID, Action: r.Action, Resource: r.Resource, Timestamp: r.Timestamp}
}

// Replay is an incremental replay of decision rows against a proposed
// permission set. Matching is action and resource only, via policy.Match;
// conditions depend on live state and are not re-evaluated.
type Replay struct {
	proposed []Permission
	max      int
	report   BlastRadius
}

// NewReplay starts a replay against proposed.
func NewReplay(proposed []Permission, opts VerifyOptions) *Replay {
	maxEx := opts.MaxExamples
	if maxEx <= 0 {
		maxEx = DefaultMaxExamples
	}
	r := &Replay{proposed: proposed, max: maxEx}
	r.report.PerPermission = make([]MatchCount, len(proposed))
	for i, p := range proposed {
		r.report.PerPermission[i].Permission = p
	}
	return r
}

// Add replays one row.
func (r *Replay) Add(row DecisionRow) {
	rep := &r.report
	class := Classify(row)
	if class == ClassInternal || class == ClassDenyOther {
		rep.IgnoredRows++
		return
	}
	hit := firstMatch(r.proposed, row.Action, row.Resource)
	if class == ClassAllow {
		rep.ReplayedAllows++
		if hit >= 0 {
			rep.StillAllowed++
			rep.PerPermission[hit].Allows++
			return
		}
		rep.NewlyDeniedCount++
		if len(rep.NewlyDenied) < r.max {
			rep.NewlyDenied = append(rep.NewlyDenied, ref(row))
		} else {
			rep.Truncated = true
		}
		return
	}
	// Denied for lack of a grant.
	if hit >= 0 {
		rep.WouldAlsoAllowCount++
		if len(rep.WouldAlsoAllow) < r.max {
			rep.WouldAlsoAllow = append(rep.WouldAlsoAllow, ref(row))
		} else {
			rep.Truncated = true
		}
	}
}

// Finish returns the report.
func (r *Replay) Finish() BlastRadius { return r.report }

// VerifyShrink proves a proposed permission set against recorded decisions:
// does it still allow every historical allow, and does it newly allow any call
// that was denied for lack of a grant? It is pure and deterministic. Rows are
// examined in the order given.
func VerifyShrink(rows iter.Seq[DecisionRow], proposed []Permission, opts VerifyOptions) BlastRadius {
	r := NewReplay(proposed, opts)
	for row := range rows {
		r.Add(row)
	}
	return r.Finish()
}

// PreviewPolicyChange is the blast radius of any permission change: which
// recorded decisions of this agent would flip if proposed were its permission
// set. It reads rows in pages and works for a shrink, a widening or a rewrite.
func PreviewPolicyChange(ctx context.Context, rows RowSource, agentID string, proposed []Permission, opts PreviewOptions) (*Preview, error) {
	r := NewReplay(proposed, opts.VerifyOptions)
	scanned := 0
	q := RowQuery{AgentID: agentID, Since: opts.Since, Until: opts.Until}
	err := walk(ctx, rows, q, opts.PageSize, func(row DecisionRow) {
		scanned++
		r.Add(row)
	})
	if err != nil {
		return nil, fmt.Errorf("shrink: preview change for agent %s: %w", agentID, err)
	}
	return &Preview{
		BlastRadius: r.Finish(), AgentID: agentID,
		Since: opts.Since, Until: opts.Until, RowsScanned: scanned,
	}, nil
}
