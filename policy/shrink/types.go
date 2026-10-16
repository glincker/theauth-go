// Package shrink applies least privilege to agent authorization. It reads the
// decisions recorded for an agent, works out which grants were never used,
// proposes a smaller permission set and replays the recorded decisions against
// it to show what would flip.
//
// Nothing is changed for you: every function reads and returns data. Matching
// reuses policy.Match, so wildcard semantics are the policy engine's own.
// Only action and resource are compared. Conditions (time windows, CIDRs,
// risk tiers) depend on live state, so they are carried over on kept
// permissions but are not re-evaluated in a replay.
package shrink

import (
	"time"

	"github.com/glincker/theauth-go/v2/policy"
)

// Result values a decision row can hold.
const (
	ResultAllowed     = "allowed"
	ResultDenied      = "denied"
	ResultRateLimited = "rate_limited"
	ResultEscalated   = "escalated"
)

// DecisionRow is the slice of an audit row the shrink tools need. It is plain
// data, so the pure functions can be driven by rows from a test, an export
// file or the audit store.
type DecisionRow struct {
	ID        string
	Action    string
	Resource  string
	Result    string
	Reason    string
	Timestamp time.Time
	// DelegationChain holds delegation grant ids recorded on the row, when the
	// writer set them.
	DelegationChain []string
}

// RowClass says how a row is treated by usage analysis.
type RowClass int

// Row classes.
const (
	// ClassInternal is a bookkeeping row (checkpoint, erasure, revoke
	// cascade, approval or delegation lifecycle). It is ignored.
	ClassInternal RowClass = iota
	// ClassAllow is an allowed call.
	ClassAllow
	// ClassDenyNoGrant is a denial that says no permission covered the call.
	// It is evidence the agent never had the grant.
	ClassDenyNoGrant
	// ClassDenyOther is a denial, rate limit or escalation for another cause.
	// It is never evidence of non-use.
	ClassDenyOther
)

// String implements fmt.Stringer.
func (c RowClass) String() string {
	switch c {
	case ClassInternal:
		return "internal"
	case ClassAllow:
		return "allow"
	case ClassDenyNoGrant:
		return "deny_no_grant"
	default:
		return "deny_other"
	}
}

// Permission is one single-action allow: an action pattern and a resource
// pattern in the policy package's glob syntax, plus the conditions of the
// statement it came from. Conditions are carried, never evaluated.
type Permission struct {
	Action     string             `json:"action"`
	Resource   string             `json:"resource"`
	Conditions []policy.Condition `json:"conditions,omitempty"`
}

// SourceKind says where a grant came from.
type SourceKind string

// Grant source kinds.
const (
	SourceOwn        SourceKind = "own"
	SourceDelegation SourceKind = "delegation"
)

// Origin records where a grant came from.
type Origin struct {
	Kind SourceKind
	// PolicyID and StatementID name the allow statement for own grants.
	PolicyID    string
	StatementID string
	// ChainID is the delegation grant id when Kind is SourceDelegation.
	ChainID string
}

// Grant is one single-action permission together with where it came from.
type Grant struct {
	Permission Permission
	Source     Origin
}

// UsedPermission is a grant with at least one allowed call attributed to it.
type UsedPermission struct {
	Permission Permission
	Count      int
	FirstSeen  time.Time
	LastSeen   time.Time
	// Via lists delegation grant ids that supplied the grant or appear on the
	// matching rows, sorted. Empty for own grants.
	Via []string
}

// Pair is a distinct (action, resource) call.
type Pair struct {
	Action   string
	Resource string
}

// UncoveredAllow is an allowed call no current grant covers (an expired
// delegation, a removed permission).
type UncoveredAllow struct {
	Pair
	Count int
}

// Evidence counts what the analysis read.
type Evidence struct {
	RowsScanned int
	AllowedRows int
	// NoGrantDenials are denials that say no permission covered the call.
	NoGrantDenials int
	// OtherDenials are denials for other causes. Never counted as non-use.
	OtherDenials int
	// InternalRows are skipped bookkeeping rows.
	InternalRows int
	// UncoveredAllows are allowed rows that no current grant covers.
	UncoveredAllows int
}

// UsageAnalysis compares what an agent is granted with what it did.
type UsageAnalysis struct {
	AgentID string
	// Since and Until are the analysed window. A zero time is unbounded.
	Since time.Time
	Until time.Time
	// Grants are the effective permissions split to one action each: own
	// first, then delegated.
	Grants []Grant
	Used   []UsedPermission
	// Unused grants have no allowed call in the window and no attempt either.
	Unused []Permission
	// AttemptedOnly grants matched only calls denied for other causes (for
	// example a rate limit). They count as in use: removing them would hide
	// the attempt.
	AttemptedOnly []Permission
	// DeniedNoGrant lists distinct pairs denied for lack of a grant, sorted
	// and capped at DistinctCap.
	DeniedNoGrant []Pair
	// Uncovered lists allowed calls no current grant covers, sorted and capped.
	Uncovered []UncoveredAllow
	Evidence  Evidence
}

// Granted returns the permissions of Grants, same order.
func (a *UsageAnalysis) Granted() []Permission {
	out := make([]Permission, len(a.Grants))
	for i, g := range a.Grants {
		out[i] = g.Permission
	}
	return out
}

// AnalyzeOptions bounds an analysis.
type AnalyzeOptions struct {
	// Since and Until bound the window. A zero time is unbounded.
	Since time.Time
	Until time.Time
	// PageSize is the rows read per query. Default 1000. Memory use is bounded
	// by it and by the distinct pairs seen.
	PageSize int
}

// Options tunes SuggestShrink.
type Options struct {
	// MinObservations is the allowed calls a permission needs to be kept.
	// Default 1.
	MinObservations int
	// Generalize merges sibling resources into a parent wildcard. Off by
	// default. A merge happens only when every merged resource was observed in
	// use, an existing grant already covers the wildcard, and the wildcard
	// matches no call that was denied for lack of a grant.
	Generalize bool
	// GeneralizeMin is the distinct observed siblings needed before they
	// merge. Default 3, minimum 2.
	GeneralizeMin int
}

// Rewrite records one generalization.
type Rewrite struct {
	From []Permission
	To   Permission
}

// Suggestion is a proposed smaller permission set.
type Suggestion struct {
	Keep     []Permission
	Remove   []Permission
	Rewrites []Rewrite
}

// RowRef identifies a replayed row.
type RowRef struct {
	ID        string
	Action    string
	Resource  string
	Timestamp time.Time
}

// MatchCount is the allows attributed to one proposed permission.
type MatchCount struct {
	Permission Permission
	Allows     int
}

// BlastRadius is the outcome of replaying recorded decisions against a
// proposed permission set.
type BlastRadius struct {
	// ReplayedAllows is the historical allowed calls replayed.
	ReplayedAllows int
	StillAllowed   int
	// NewlyDeniedCount is exact. NewlyDenied may be capped.
	NewlyDeniedCount int
	NewlyDenied      []RowRef
	// WouldAlsoAllowCount counts calls denied for lack of a grant that the
	// proposal would allow. WouldAlsoAllow may be capped.
	WouldAlsoAllowCount int
	WouldAlsoAllow      []RowRef
	// IgnoredRows are denials for other causes and bookkeeping rows.
	IgnoredRows int
	// PerPermission is allows per proposed permission, same order as the
	// proposal.
	PerPermission []MatchCount
	// Truncated is true when a list above was cut at MaxExamples. Counts are
	// always exact.
	Truncated bool
}

// VerifyOptions bounds the example lists of a replay.
type VerifyOptions struct {
	// MaxExamples is the most rows listed in each example list. Default 1000.
	MaxExamples int
}

// PreviewOptions bounds PreviewPolicyChange.
type PreviewOptions struct {
	VerifyOptions
	Since    time.Time
	Until    time.Time
	PageSize int
}

// Preview is a BlastRadius for one agent and window.
type Preview struct {
	BlastRadius
	AgentID     string
	Since       time.Time
	Until       time.Time
	RowsScanned int
}
