package device

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/policy/pathmatch"
)

// testdata/attestation-policy-vectors.json is produced by docs-local/vectors/gen-attest-policy-vectors.mts
// from the TypeScript evaluateDeviceBundle. Each case must give the same allowed flag, code and
// refusal sentence here.
func TestAttestationPolicyVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/attestation-policy-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			Name    string         `json:"name"`
			Claims  map[string]any `json:"claims"`
			Request struct {
				Action    string         `json:"action"`
				Resource  string         `json:"resource"`
				NowMs     int64          `json:"nowMs"`
				Arguments map[string]any `json:"arguments"`
				IP        string         `json:"ip"`
				Calls     *int           `json:"callsInLastHour"`
			} `json:"request"`
			Expect struct {
				Allowed bool   `json:"allowed"`
				Code    string `json:"code"`
				Reason  string `json:"reason"`
			} `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) < 200 {
		t.Fatalf("only %d cases", len(file.Cases))
	}
	for _, tc := range file.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			c := &Claims{Exp: int64(tc.Claims["exp"].(float64)), ResourceMatching: pathmatch.Colon}
			for _, pv := range tc.Claims["perms"].([]any) {
				if p, ok := parsePermission(pv); ok {
					c.Perms = append(c.Perms, p)
				}
			}
			c.Attestation = parseFacts(tc.Claims["att"])
			opts := []Option{WithNow(time.UnixMilli(tc.Request.NowMs))}
			if tc.Request.Arguments != nil {
				opts = append(opts, WithArguments(tc.Request.Arguments))
			}
			if tc.Request.IP != "" {
				opts = append(opts, WithIP(tc.Request.IP))
			}
			if tc.Request.Calls != nil {
				opts = append(opts, WithCallsInLastHour(*tc.Request.Calls))
			}
			got := Evaluate(c, tc.Request.Action, tc.Request.Resource, opts...)
			if got.Allowed != tc.Expect.Allowed || got.Code != tc.Expect.Code || got.Reason != tc.Expect.Reason {
				t.Fatalf("got %+v, TS says %+v", got, tc.Expect)
			}
		})
	}
}

func TestAttestationClaimRoundTripsThroughSignedBundle(t *testing.T) {
	c := Claims{
		Issuer: DefaultIssuer, Subject: "d1", Audience: "d1", Exp: 100, Perms: []Permission{{
			Resource: "door:*", Actions: []string{"unlock"},
			Constraints: &Constraints{Attestation: NewAttestationConstraint(LevelStrongbox, nil, []string{"a"})},
		}},
		Attestation: &AttestationFacts{Format: "f", SecurityLevel: LevelStrongbox, BootState: BootVerified, AppIDs: []string{"a"}},
	}
	m := c.Map()
	b, _ := json.Marshal(m)
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	facts := parseFacts(back["att"])
	if facts == nil || facts.SecurityLevel != LevelStrongbox || facts.BootState != BootVerified || len(facts.AppIDs) != 1 {
		t.Fatalf("facts: %+v", facts)
	}
	p, ok := parsePermission(back["perms"].([]any)[0])
	if !ok || p.Constraints.Attestation == nil || p.Constraints.Attestation.MinSecurityLevel != LevelStrongbox {
		t.Fatalf("perm: %+v", p)
	}
	d := Evaluate(&Claims{Exp: 1 << 40, Perms: []Permission{p}, Attestation: facts}, "unlock", "door:x", WithNow(time.Unix(1, 0)))
	if !d.Allowed {
		t.Fatalf("decision: %+v", d)
	}
}
