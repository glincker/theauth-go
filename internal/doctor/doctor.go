// Package doctor evaluates security-posture checks over a plain input struct.
package doctor

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/apitokens"
)

// Severity ranks a doctor finding.
type Severity string

// Doctor severities, most serious first.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rank orders severities, higher is more serious. Unknown values rank 0.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// Finding is one security-posture observation. Detail carries counts and
// settings only, never secrets, tokens or user identifiers.
type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation"`
	DocsAnchor  string   `json:"docsAnchor"`
}

// Report is the result of TheAuth.Doctor.
type Report struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	Summary     map[Severity]int `json:"summary"`
	Findings    []Finding        `json:"findings"`
}

// MaxSeverity returns the highest severity present, or "" for a clean report.
func (r Report) MaxSeverity() Severity {
	var max Severity
	for _, f := range r.Findings {
		if f.Severity.Rank() > max.Rank() {
			max = f.Severity
		}
	}
	return max
}

// UnknownCount marks a count whose storage capability is unavailable.
const UnknownCount = -1

// Input is the pure-data view of config and storage that checks read.
// Counts of UnknownCount mean the storage capability is unavailable.
type Input struct {
	Now time.Time

	BaseURL      string
	SecureCookie bool

	RateLimitPerIP, RateLimitPerEmail int
	TrustedProxies                    int
	CSRFDisabled                      bool

	ThrottleDisabled bool
	GraceFailures    int
	UserMaxFailures  int
	MFAMaxFailures   int

	PasswordMinLength int
	HasBreachChecker  bool

	BootstrapOn     bool
	BootstrapOpen   bool
	UserCount       int
	OAuthSignupOpen bool
	OAuthDomains    int
	HasProviders    bool
	HasSAML         bool
	OAuthReturnTo   int

	TOTPEnabled     bool
	WebAuthnEnabled bool
	AdminCount      int
	AdminsWithoutMF int

	SessionTTL  time.Duration
	IdleTimeout time.Duration

	TokensKnown        bool
	TokensNoExpiry     int
	TokensBeyondYear   int
	TokensRoot         int
	AgentTokensLong    int
	TokensExpired      int
	SessionsExpired    int
	EncryptionKeyLen   int
	EncryptionNeeded   bool
	AuditConfigured    bool
	AuditSinkCount     int
	WebAuthnRPID       string
	WebAuthnOrigins    []string
	WebAuthnConfigured bool
}

// Build runs every check over in and returns the sorted report.
func Build(in Input) Report {
	var out []Finding
	for _, c := range doctorChecks {
		out = append(out, c(in)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := out[i].Severity.Rank(), out[j].Severity.Rank(); ri != rj {
			return ri > rj
		}
		return out[i].ID < out[j].ID
	})
	sum := map[Severity]int{SeverityCritical: 0, SeverityHigh: 0, SeverityMedium: 0, SeverityLow: 0, SeverityInfo: 0}
	for _, f := range out {
		sum[f.Severity]++
	}
	if out == nil {
		out = []Finding{}
	}
	return Report{GeneratedAt: in.Now, Summary: sum, Findings: out}
}

// TallyTokens counts the token facts the checks read into in.
func TallyTokens(in *Input, toks []apitokens.APIToken) {
	for _, t := range toks {
		if t.RevokedAt != nil {
			continue
		}
		expired := t.ExpiresAt != nil && !in.Now.Before(*t.ExpiresAt)
		if expired {
			in.TokensExpired++
			continue
		}
		if t.ExpiresAt == nil {
			in.TokensNoExpiry++
		} else if t.ExpiresAt.Sub(t.CreatedAt) > 365*24*time.Hour {
			in.TokensBeyondYear++
		}
		if t.Kind == apitokens.APITokenKindAgent && (t.ExpiresAt == nil || t.ExpiresAt.Sub(t.CreatedAt) > 24*time.Hour) {
			in.AgentTokensLong++
		}
		for _, ab := range t.Abilities {
			if ab == apitokens.AbilityRoot {
				in.TokensRoot++
				break
			}
		}
	}
}

func baseHost(baseURL string) (host string, https bool) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", false
	}
	return strings.ToLower(u.Hostname()), strings.EqualFold(u.Scheme, "https")
}

func isLocalHost(h string) bool {
	return h == "localhost" || h == "::1" || strings.HasSuffix(h, ".localhost") || strings.HasPrefix(h, "127.")
}

func fnd(id string, sev Severity, title, detail, fix string) Finding {
	return Finding{ID: id, Severity: sev, Title: title, Detail: detail, Remediation: fix, DocsAnchor: "security-doctor.md#" + strings.ReplaceAll(strings.ToLower(id), ".", "-")}
}

func plural(n int, one string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %ss", n, one)
}
