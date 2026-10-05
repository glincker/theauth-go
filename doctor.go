package theauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"
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

// DoctorAdminLister is the optional storage capability that lets Doctor check
// second-factor coverage for administrators.
type DoctorAdminLister interface {
	// ListAdminUserIDs returns the IDs of every user holding an admin role.
	ListAdminUserIDs(ctx context.Context) ([]ULID, error)
}

// DoctorSessionCounter is the optional storage capability that lets Doctor
// count sessions that expired but were never pruned.
type DoctorSessionCounter interface {
	// CountExpiredSessions counts sessions whose expiry is before the cutoff.
	CountExpiredSessions(ctx context.Context, before time.Time) (int, error)
}

const unknownCount = -1

// doctorInput is the pure-data view of config and storage that checks read.
// Counts of unknownCount mean the storage capability is unavailable.
type doctorInput struct {
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

	BootstrapOn       bool
	BootstrapOpen     bool
	UserCount         int
	OAuthSignupPolicy OAuthSignupPolicy
	OAuthDomains      int
	HasProviders      bool
	HasSAML           bool
	OAuthReturnTo     int

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

// Doctor inspects the live Config and storage and reports security-posture
// findings, most serious first. It never mutates state and never includes
// secrets in the report.
func (a *TheAuth) Doctor(ctx context.Context) Report {
	return buildReport(a.gatherDoctorInput(ctx, time.Now().UTC()))
}

func buildReport(in doctorInput) Report {
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

func (a *TheAuth) gatherDoctorInput(ctx context.Context, now time.Time) doctorInput {
	cfg := a.doctorCfg
	in := doctorInput{
		Now:               now,
		BaseURL:           cfg.BaseURL,
		SecureCookie:      cfg.SecureCookie,
		RateLimitPerIP:    cfg.RateLimitPerIP,
		RateLimitPerEmail: cfg.RateLimitPerEmail,
		TrustedProxies:    len(cfg.TrustedProxies),
		CSRFDisabled:      cfg.DisableCSRFProtection,
		PasswordMinLength: cfg.PasswordPolicy.MinLength,
		HasBreachChecker:  cfg.PasswordPolicy.BreachChecker != nil,
		BootstrapOn:       cfg.Bootstrap != nil,
		UserCount:         unknownCount,
		HasProviders:      len(cfg.Providers) > 0,
		HasSAML:           cfg.SAML != nil,
		TOTPEnabled:       cfg.TOTP != nil,
		WebAuthnEnabled:   cfg.WebAuthn != nil,
		AdminCount:        unknownCount,
		AdminsWithoutMF:   unknownCount,
		SessionTTL:        cfg.SessionTTL,
		IdleTimeout:       cfg.SessionIdleTimeout,
		SessionsExpired:   unknownCount,
		EncryptionKeyLen:  len(cfg.EncryptionKey),
		EncryptionNeeded:  len(cfg.Providers) > 0 || cfg.TOTP != nil,
		AuditConfigured:   cfg.Audit != nil,
	}
	if in.PasswordMinLength <= 0 {
		in.PasswordMinLength = 12
	}
	if cfg.Bootstrap != nil {
		in.BootstrapOpen = cfg.Bootstrap.OpenSignupAfterFirstUser
	}
	if cfg.Audit != nil {
		in.AuditSinkCount = len(cfg.Audit.Sinks)
	}
	in.GraceFailures, in.UserMaxFailures, in.MFAMaxFailures = 3, 10, 5
	if t := cfg.LoginThrottle; t != nil {
		in.ThrottleDisabled = t.Disabled
		if t.GraceFailures > 0 {
			in.GraceFailures = t.GraceFailures
		}
		if t.UserMaxFailures > 0 {
			in.UserMaxFailures = t.UserMaxFailures
		}
		if t.MFAMaxFailures > 0 {
			in.MFAMaxFailures = t.MFAMaxFailures
		}
	}
	in.OAuthSignupPolicy = OAuthSignupOpen
	if o := cfg.OAuth; o != nil {
		if o.Signup != "" {
			in.OAuthSignupPolicy = o.Signup
		}
		in.OAuthDomains = len(o.AllowedEmailDomains)
		in.OAuthReturnTo = len(o.AllowedReturnTo)
	}
	if w := cfg.WebAuthn; w != nil {
		in.WebAuthnConfigured = true
		in.WebAuthnRPID = w.RPID
		in.WebAuthnOrigins = append([]string(nil), w.RPOrigins...)
	}
	a.gatherStorageFacts(ctx, &in)
	return in
}

func (a *TheAuth) gatherStorageFacts(ctx context.Context, in *doctorInput) {
	raw := a.storageRaw
	if c, ok := raw.(UserCountStorage); ok {
		if n, err := c.CountUsers(ctx); err == nil {
			in.UserCount = n
		} else {
			slog.Warn("theauth: doctor: count users failed", "err", err.Error())
		}
	}
	if s, ok := raw.(DoctorSessionCounter); ok {
		if n, err := s.CountExpiredSessions(ctx, in.Now); err == nil {
			in.SessionsExpired = n
		} else {
			slog.Warn("theauth: doctor: count expired sessions failed", "err", err.Error())
		}
	}
	if a.apiTokens != nil {
		if toks, err := a.apiTokens.ListAll(ctx); err == nil {
			in.TokensKnown = true
			tallyTokens(in, toks)
		} else {
			slog.Warn("theauth: doctor: list api tokens failed", "err", err.Error())
		}
	}
	if l, ok := raw.(DoctorAdminLister); ok && in.TOTPEnabled {
		a.tallyAdminMFA(ctx, in, l)
	}
}

func (a *TheAuth) tallyAdminMFA(ctx context.Context, in *doctorInput, l DoctorAdminLister) {
	ts, ok := a.storageRaw.(TOTPStorage)
	if !ok {
		return
	}
	ids, err := l.ListAdminUserIDs(ctx)
	if err != nil {
		slog.Warn("theauth: doctor: list admins failed", "err", err.Error())
		return
	}
	in.AdminCount = len(ids)
	in.AdminsWithoutMF = 0
	for _, id := range ids {
		sec, err := ts.TOTPSecretByUserID(ctx, id)
		if err != nil || sec == nil || sec.ConfirmedAt == nil {
			in.AdminsWithoutMF++
		}
	}
}

func tallyTokens(in *doctorInput, toks []APIToken) {
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
		if t.Kind == APITokenKindAgent && (t.ExpiresAt == nil || t.ExpiresAt.Sub(t.CreatedAt) > 24*time.Hour) {
			in.AgentTokensLong++
		}
		for _, ab := range t.Abilities {
			if ab == AbilityRoot {
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
