package policy

// Requirement is what a risk tier or escalate statement demands before the
// action may run.
type Requirement string

// Requirements. RequireNone lets the request through unchanged.
const (
	RequireNone     Requirement = "none"
	RequireApproval Requirement = "approval"
	RequireStepUp   Requirement = "step_up"
)

// Escalation explains why a request needs more than a plain allow.
type Escalation struct {
	Tier        string      `json:"tier,omitempty"`
	Requirement Requirement `json:"requirement"`
	Reason      string      `json:"reason"`
}

// RiskTier maps request risk attributes to a requirement. Every set field
// must hold for the tier to match.
type RiskTier struct {
	Name string
	// MinAmount matches when Request.Amount is at least this value.
	// Zero disables the check.
	MinAmount float64
	// Currency, when set, must equal Request.Currency.
	Currency string
	// DataClasses, when set, must contain Request.DataClass.
	DataClasses []string
	// Irreversible, when non-nil, must equal Request.Irreversible.
	Irreversible *bool
	Require      Requirement
}

func (t RiskTier) matches(req Request) bool {
	if t.MinAmount > 0 && req.Amount < t.MinAmount {
		return false
	}
	if t.Currency != "" && t.Currency != req.Currency {
		return false
	}
	if len(t.DataClasses) > 0 {
		found := false
		for _, c := range t.DataClasses {
			if c == req.DataClass {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if t.Irreversible != nil && *t.Irreversible != req.Irreversible {
		return false
	}
	return true
}

func (r Requirement) strength() int {
	switch r {
	case RequireStepUp:
		return 2
	case RequireApproval:
		return 1
	}
	return 0
}

// Classify returns the strongest matching tier (first wins on ties), or false
// when no tier matches or the match requires nothing.
func (e Evaluator) Classify(req Request) (RiskTier, bool) {
	var best RiskTier
	found := false
	for _, t := range e.Risk {
		if !t.matches(req) {
			continue
		}
		if !found || t.Require.strength() > best.Require.strength() {
			best, found = t, true
		}
	}
	if !found || best.Require.strength() == 0 {
		return RiskTier{}, false
	}
	return best, true
}

// applyRisk turns an allow into an escalate when a risk tier demands it.
func (e Evaluator) applyRisk(req Request, d Decision) Decision {
	t, ok := e.Classify(req)
	if !ok {
		return d
	}
	d.Allowed = false
	d.Effect = Escalate
	d.Reason = "risk tier " + t.Name + " requires " + string(t.Require)
	d.Escalation = &Escalation{Tier: t.Name, Requirement: t.Require, Reason: d.Reason}
	return d
}
