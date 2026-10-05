package theauth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/v2/internal/doctor"
	"github.com/go-chi/chi/v5"
)

// Severity ranks a doctor finding.
type Severity = doctor.Severity

// Doctor severities, most serious first.
const (
	SeverityCritical = doctor.SeverityCritical
	SeverityHigh     = doctor.SeverityHigh
	SeverityMedium   = doctor.SeverityMedium
	SeverityLow      = doctor.SeverityLow
	SeverityInfo     = doctor.SeverityInfo
)

// Finding is one security-posture observation.
type Finding = doctor.Finding

// Report is the result of TheAuth.Doctor.
type Report = doctor.Report

// Doctor finding IDs. They are stable and appear in docs/SECURITY-DOCTOR.md.
const (
	DoctorSignupOpen        = doctor.DoctorSignupOpen
	DoctorBootstrapOff      = doctor.DoctorBootstrapOff
	DoctorTrustedProxies    = doctor.DoctorTrustedProxies
	DoctorSecureCookie      = doctor.DoctorSecureCookie
	DoctorCSRFDisabled      = doctor.DoctorCSRFDisabled
	DoctorThrottleDisabled  = doctor.DoctorThrottleDisabled
	DoctorThrottleLax       = doctor.DoctorThrottleLax
	DoctorPasswordMinLength = doctor.DoctorPasswordMinLength
	DoctorPasswordNoBreach  = doctor.DoctorPasswordNoBreach
	DoctorAdminNoTOTP       = doctor.DoctorAdminNoTOTP
	DoctorNoSecondFactor    = doctor.DoctorNoSecondFactor
	DoctorSessionTTLLong    = doctor.DoctorSessionTTLLong
	DoctorSessionNoIdle     = doctor.DoctorSessionNoIdle
	DoctorTokenNoExpiry     = doctor.DoctorTokenNoExpiry
	DoctorTokenLongExpiry   = doctor.DoctorTokenLongExpiry
	DoctorTokenRoot         = doctor.DoctorTokenRoot
	DoctorAgentTokenLong    = doctor.DoctorAgentTokenLong
	DoctorTokensUnpruned    = doctor.DoctorTokensUnpruned
	DoctorSessionsUnpruned  = doctor.DoctorSessionsUnpruned
	DoctorEncryptionKey     = doctor.DoctorEncryptionKey
	DoctorAuditSink         = doctor.DoctorAuditSink
	DoctorWebAuthnRPID      = doctor.DoctorWebAuthnRPID
	DoctorRedirectAllowList = doctor.DoctorRedirectAllowList
)

// DoctorFindingIDs lists every finding ID a check can emit.
func DoctorFindingIDs() []string { return doctor.DoctorFindingIDs() }

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

// Doctor inspects the live Config and storage and reports security-posture
// findings, most serious first. It never mutates state and never includes
// secrets in the report.
func (a *TheAuth) Doctor(ctx context.Context) Report {
	return doctor.Build(a.gatherDoctorInput(ctx, time.Now().UTC()))
}

func (a *TheAuth) gatherDoctorInput(ctx context.Context, now time.Time) doctor.Input {
	cfg := a.doctorCfg
	in := doctor.Input{
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
		UserCount:         doctor.UnknownCount,
		HasProviders:      len(cfg.Providers) > 0,
		HasSAML:           cfg.SAML != nil,
		TOTPEnabled:       cfg.TOTP != nil,
		WebAuthnEnabled:   cfg.WebAuthn != nil,
		AdminCount:        doctor.UnknownCount,
		AdminsWithoutMF:   doctor.UnknownCount,
		SessionTTL:        cfg.SessionTTL,
		IdleTimeout:       cfg.SessionIdleTimeout,
		SessionsExpired:   doctor.UnknownCount,
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
	in.OAuthSignupOpen = true
	if o := cfg.OAuth; o != nil {
		if o.Signup != "" {
			in.OAuthSignupOpen = o.Signup == OAuthSignupOpen
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

func (a *TheAuth) gatherStorageFacts(ctx context.Context, in *doctor.Input) {
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
			doctor.TallyTokens(in, toks)
		} else {
			slog.Warn("theauth: doctor: list api tokens failed", "err", err.Error())
		}
	}
	if l, ok := raw.(DoctorAdminLister); ok && in.TOTPEnabled {
		a.tallyAdminMFA(ctx, in, l)
	}
}

func (a *TheAuth) tallyAdminMFA(ctx context.Context, in *doctor.Input, l DoctorAdminLister) {
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

// mountDoctor serves GET /auth/admin/doctor for callers holding the root
// ability, via session or API bearer token.
func (a *TheAuth) mountDoctor(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	r.With(ipLimit, a.RequireAbility(AbilityRoot)).Get("/admin/doctor", a.handleDoctor)
}

func (a *TheAuth) handleDoctor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(a.Doctor(r.Context()))
}
