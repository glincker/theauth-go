package visitorsignal

// Outcome is what the collector or verifier may do for a request.
type Outcome string

// Consent outcomes.
const (
	// OutcomeRun allows full collection and a persistent hash.
	OutcomeRun Outcome = "run"
	// OutcomeSuppressed means no components are collected, with a reason.
	OutcomeSuppressed Outcome = "suppressed"
	// OutcomeBotFlagsOnly allows automation flags but no persistent hash.
	OutcomeBotFlagsOnly Outcome = "bot_flags_only"
)

// ConsentInput is the plain consent input from SPEC.md.
type ConsentInput struct {
	Consent        ConsentState
	GPC            bool
	DNT            bool
	RouteProtected bool
	LawfulBasis    LawfulBasis
}

// Decision is the result of Decide. Reason is set only for OutcomeSuppressed.
type Decision struct {
	Outcome Outcome
	Reason  SuppressedReason
}

// Decide applies the consent matrix. Precedence where two rows apply: the
// consent or route suppression wins over DNT and GPC, because nothing is
// collected at all, and DNT or GPC win over a lawful basis or a granted
// consent by leaving only bot flags. A mode that is off or unknown returns
// mode_not_allowed.
func Decide(mode Mode, in ConsentInput) (Decision, error) {
	granted := in.Consent == ConsentGranted
	switch mode {
	case ModeAnalytics:
		if !granted {
			return suppressedForConsent(in), nil
		}
		if r, ok := privacySignal(in); ok {
			return Decision{Outcome: OutcomeSuppressed, Reason: r}, nil
		}
		return Decision{Outcome: OutcomeRun}, nil
	case ModeFraudPrevention:
		basis := in.LawfulBasis == LawfulBasisLegitimateInterestSecurity && in.RouteProtected
		if !granted && !basis {
			if in.LawfulBasis == LawfulBasisLegitimateInterestSecurity && !in.RouteProtected {
				return Decision{Outcome: OutcomeSuppressed, Reason: ReasonRouteNotProtected}, nil
			}
			return suppressedForConsent(in), nil
		}
		if in.DNT || in.GPC {
			return Decision{Outcome: OutcomeBotFlagsOnly}, nil
		}
		return Decision{Outcome: OutcomeRun}, nil
	default:
		return Decision{}, newError(CodeModeNotAllowed, "mode is not enabled")
	}
}

func suppressedForConsent(in ConsentInput) Decision {
	if in.Consent == ConsentDenied {
		return Decision{Outcome: OutcomeSuppressed, Reason: ReasonConsentDenied}
	}
	return Decision{Outcome: OutcomeSuppressed, Reason: ReasonConsentUnknown}
}

func privacySignal(in ConsentInput) (SuppressedReason, bool) {
	switch {
	case in.DNT:
		return ReasonDNT, true
	case in.GPC:
		return ReasonGPC, true
	}
	return "", false
}
