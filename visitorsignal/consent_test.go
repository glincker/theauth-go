package visitorsignal

import (
	"fmt"
	"testing"
)

func TestDecideMatrix(t *testing.T) {
	t.Parallel()
	run := Decision{Outcome: OutcomeRun}
	flags := Decision{Outcome: OutcomeBotFlagsOnly}
	sup := func(r SuppressedReason) Decision { return Decision{Outcome: OutcomeSuppressed, Reason: r} }
	basis := LawfulBasisLegitimateInterestSecurity

	// expect computes the SPEC matrix independently of Decide's branch order.
	expect := func(mode Mode, in ConsentInput) Decision {
		granted := in.Consent == ConsentGranted
		denial := ReasonConsentUnknown
		if in.Consent == ConsentDenied {
			denial = ReasonConsentDenied
		}
		privacy := in.DNT || in.GPC
		if mode == ModeAnalytics {
			switch {
			case !granted:
				return sup(denial)
			case in.DNT:
				return sup(ReasonDNT)
			case in.GPC:
				return sup(ReasonGPC)
			}
			return run
		}
		asserted := in.LawfulBasis == basis
		switch {
		case granted || (asserted && in.RouteProtected):
			if privacy {
				return flags
			}
			return run
		case asserted:
			return sup(ReasonRouteNotProtected)
		}
		return sup(denial)
	}

	for _, mode := range []Mode{ModeAnalytics, ModeFraudPrevention} {
		for _, consent := range []ConsentState{ConsentGranted, ConsentDenied, ConsentUnknown, ""} {
			for _, dnt := range []bool{false, true} {
				for _, gpc := range []bool{false, true} {
					for _, protected := range []bool{false, true} {
						for _, lb := range []LawfulBasis{"", basis, "other"} {
							in := ConsentInput{Consent: consent, DNT: dnt, GPC: gpc, RouteProtected: protected, LawfulBasis: lb}
							name := fmt.Sprintf("%s/c=%s/dnt=%t/gpc=%t/prot=%t/lb=%s", mode, consent, dnt, gpc, protected, lb)
							t.Run(name, func(t *testing.T) {
								t.Parallel()
								got, err := Decide(mode, in)
								if err != nil {
									t.Fatal(err)
								}
								if want := expect(mode, in); got != want {
									t.Fatalf("got %+v, want %+v", got, want)
								}
							})
						}
					}
				}
			}
		}
	}
}

func TestDecideSpecRows(t *testing.T) {
	t.Parallel()
	basis := LawfulBasisLegitimateInterestSecurity
	tests := []struct {
		name string
		mode Mode
		in   ConsentInput
		want Decision
	}{
		{"analytics_denied", ModeAnalytics, ConsentInput{Consent: ConsentDenied}, Decision{OutcomeSuppressed, ReasonConsentDenied}},
		{"analytics_unknown", ModeAnalytics, ConsentInput{Consent: ConsentUnknown}, Decision{OutcomeSuppressed, ReasonConsentUnknown}},
		{"analytics_dnt", ModeAnalytics, ConsentInput{Consent: ConsentGranted, DNT: true}, Decision{OutcomeSuppressed, ReasonDNT}},
		{"analytics_gpc", ModeAnalytics, ConsentInput{Consent: ConsentGranted, GPC: true}, Decision{OutcomeSuppressed, ReasonGPC}},
		{"analytics_basis_does_not_help", ModeAnalytics, ConsentInput{Consent: ConsentUnknown, LawfulBasis: basis, RouteProtected: true}, Decision{OutcomeSuppressed, ReasonConsentUnknown}},
		{"fraud_basis_protected_runs", ModeFraudPrevention, ConsentInput{Consent: ConsentUnknown, LawfulBasis: basis, RouteProtected: true}, Decision{OutcomeRun, ""}},
		{"fraud_basis_protected_dnt", ModeFraudPrevention, ConsentInput{Consent: ConsentDenied, LawfulBasis: basis, RouteProtected: true, DNT: true}, Decision{OutcomeBotFlagsOnly, ""}},
		{"fraud_no_basis_denied", ModeFraudPrevention, ConsentInput{Consent: ConsentDenied, RouteProtected: true}, Decision{OutcomeSuppressed, ReasonConsentDenied}},
		{"fraud_granted_unprotected", ModeFraudPrevention, ConsentInput{Consent: ConsentGranted}, Decision{OutcomeRun, ""}},
		{"fraud_basis_unprotected", ModeFraudPrevention, ConsentInput{Consent: ConsentUnknown, LawfulBasis: basis}, Decision{OutcomeSuppressed, ReasonRouteNotProtected}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Decide(tc.mode, tc.in)
			if err != nil || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}

func TestDecideModeNotAllowed(t *testing.T) {
	t.Parallel()
	for _, mode := range []Mode{ModeOff, "", "other"} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			if _, err := Decide(mode, ConsentInput{Consent: ConsentGranted}); CodeOf(err) != CodeModeNotAllowed {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
