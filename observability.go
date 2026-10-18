package theauth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/authevents"
	"github.com/glincker/theauth-go/v2/internal/doctor"
	"github.com/glincker/theauth-go/v2/internal/observability"
	"github.com/go-chi/chi/v5"
)

// Observability re-exports the adapter types for tracing and metrics. Implementations live in
// internal/observability. Adapters keep vendor SDKs (OpenTelemetry, Prometheus) out of this module.
// Keep high-cardinality identifiers (client_id, user_id, IP) on spans, never on metric labels. See
// examples/observability-otel and observability-prom.

// Tracer starts spans. Adapters implement it; see internal/observability.Tracer for the contract.
type Tracer = observability.Tracer

// Span is the per-operation span handle.
type Span = observability.Span

// Attr is one key/value pair attached to a span.
type Attr = observability.Attr

// StringAttr wraps a string-valued span attribute.
func StringAttr(k, v string) Attr { return observability.StringAttr(k, v) }

// IntAttr wraps an int64 span attribute.
func IntAttr(k string, v int64) Attr { return observability.IntAttr(k, v) }

// BoolAttr wraps a bool span attribute.
func BoolAttr(k string, v bool) Attr { return observability.BoolAttr(k, v) }

// ErrAttr wraps an error as a string span attribute under the key "error".
func ErrAttr(err error) Attr { return observability.ErrAttr(err) }

// Metrics is the instrument factory that adapters implement.
type Metrics = observability.Metrics

// Counter is a monotonic counter.
type Counter = observability.Counter

// Histogram is a distribution histogram.
type Histogram = observability.Histogram

// Gauge is a settable, incrementable, decrementable instantaneous value.
type Gauge = observability.Gauge

// Labels is the name-to-value label set for one metric instance. Never put high-cardinality
// identifiers in it.
type Labels = observability.Labels

// Hooks bundles the observability adapters attached to Config.Observability. Either field may be
// nil; the library falls back to no-op adapters per field.
type Hooks = observability.Hooks

// Status is the canonical span / metric status enum used across every instrumented operation in the
// library.
type Status = observability.Status

const (
	StatusSuccess = observability.StatusSuccess
	StatusError   = observability.StatusError

	SpanOAuthToken             = observability.SpanOAuthToken
	SpanOAuthIntrospect        = observability.SpanOAuthIntrospect
	SpanOAuthRevoke            = observability.SpanOAuthRevoke
	SpanOAuthAuthorize         = observability.SpanOAuthAuthorize
	SpanOAuthDCRRegister       = observability.SpanOAuthDCRRegister
	SpanSessionCreate          = observability.SpanSessionCreate
	SpanSessionRevoke          = observability.SpanSessionRevoke
	SpanPasswordVerify         = observability.SpanPasswordVerify
	SpanWebauthnRegisterBegin  = observability.SpanWebauthnRegisterBegin
	SpanWebauthnRegisterFinish = observability.SpanWebauthnRegisterFinish
	SpanWebauthnLoginBegin     = observability.SpanWebauthnLoginBegin
	SpanWebauthnLoginFinish    = observability.SpanWebauthnLoginFinish
	SpanTOTPVerify             = observability.SpanTOTPVerify
	SpanSAMLACS                = observability.SpanSAMLACS
	SpanSCIMUsersList          = observability.SpanSCIMUsersList
	SpanSCIMUsersGet           = observability.SpanSCIMUsersGet
	SpanSCIMUsersPost          = observability.SpanSCIMUsersPost
	SpanSCIMUsersPatch         = observability.SpanSCIMUsersPatch
	SpanSCIMUsersDelete        = observability.SpanSCIMUsersDelete
	SpanAgentCreate            = observability.SpanAgentCreate
	SpanAgentSuspend           = observability.SpanAgentSuspend
	SpanAgentRevoke            = observability.SpanAgentRevoke
	SpanDelegationGrant        = observability.SpanDelegationGrant
	SpanDelegationRevoke       = observability.SpanDelegationRevoke

	MetricOAuthTokenRequestsTotal      = observability.MetricOAuthTokenRequestsTotal
	MetricOAuthTokenLatency            = observability.MetricOAuthTokenLatency
	MetricOAuthIntrospectRequestsTotal = observability.MetricOAuthIntrospectRequestsTotal
	MetricOAuthIntrospectLatency       = observability.MetricOAuthIntrospectLatency
	MetricClientAuthCacheHits          = observability.MetricClientAuthCacheHits
	MetricClientAuthCacheMisses        = observability.MetricClientAuthCacheMisses
	MetricClientAuthCacheSize          = observability.MetricClientAuthCacheSize
	MetricRateLimitBlockedTotal        = observability.MetricRateLimitBlockedTotal
	MetricAgentPolicyResolverErrors    = observability.MetricAgentPolicyResolverErrors
	MetricAuditDroppedTotal            = observability.MetricAuditDroppedTotal
	MetricAuditQueueDepth              = observability.MetricAuditQueueDepth
	MetricSessionActive                = observability.MetricSessionActive
	MetricWebAuthnChallengesInFlight   = observability.MetricWebAuthnChallengesInFlight
	MetricSAMLInFlightAuthnReq         = observability.MetricSAMLInFlightAuthnReq

	AttrStatus    = observability.AttrStatus
	AttrGrantType = observability.AttrGrantType
	AttrClientID  = observability.AttrClientID
	AttrErrorCode = observability.AttrErrorCode
	AttrSubject   = observability.AttrSubject
	AttrScope     = observability.AttrScope
	AttrResource  = observability.AttrResource
	AttrTenantID  = observability.AttrTenantID
	AttrRule      = observability.AttrRule
	AttrKind      = observability.AttrKind
)

// LatencyBuckets is the shared histogram layout for every _latency_seconds metric. Consumers
// pre-registering histograms must use this exact slice so bucket boundaries line up.
var LatencyBuckets = observability.LatencyBuckets

// coalesceHooks returns a non-nil *Hooks so internal services need no nil check on the pointer.
func coalesceHooks(h *Hooks) *Hooks {
	if h == nil {
		return &Hooks{}
	}
	return h
}

// ObservabilityHooks returns the bundle in use, never nil, so custom services can share the same adapters.
func (a *TheAuth) ObservabilityHooks() *Hooks {
	if a == nil {
		return &Hooks{}
	}
	return a.hooks
}

// DefaultRedactor masks values for password, secret, token, code, refresh_token and access_token
// keys at any depth.
func DefaultRedactor(metadata map[string]any) map[string]any { return audit.DefaultRedactor(metadata) }

// SeededSecretKeys returns a copy of the key blocklist the default redactor applies.
func SeededSecretKeys() []string { return audit.SeededSecretKeys() }

// HashEmailForAudit returns the hex sha256 of the lowercased email.
func HashEmailForAudit(email string) string { return audit.HashEmailForAudit(email) }

// AuditSink streams audit events to an external system. Sinks are best effort: a failed Stream
// never blocks canonical writes and is counted in Stats.AuditSinkFailed. Built-in sinks live under
// audit/sinks/ (otlp, splunkhec, webhook).
type AuditSink interface {
	Stream(ctx context.Context, batch []AuditEvent) error

	Name() string
}

// AuthEventType names one security-relevant authentication event.
type AuthEventType = authevents.Type

const (
	AuthEventLoginSuccess           = authevents.LoginSuccess
	AuthEventLoginFailure           = authevents.LoginFailure
	AuthEventMFASuccess             = authevents.MFASuccess
	AuthEventMFAFailure             = authevents.MFAFailure
	AuthEventPasswordChanged        = authevents.PasswordChanged
	AuthEventPasswordResetRequested = authevents.PasswordResetRequested
	AuthEventPasswordResetCompleted = authevents.PasswordResetCompleted
	AuthEventPasskeyAdded           = authevents.PasskeyAdded
	AuthEventPasskeyRemoved         = authevents.PasskeyRemoved
	AuthEventPasskeyRenamed         = authevents.PasskeyRenamed
	AuthEventPasskeyCloneWarning    = authevents.PasskeyCloneWarning
	AuthEventTOTPEnrolled           = authevents.TOTPEnrolled
	AuthEventTOTPDisabled           = authevents.TOTPDisabled
	AuthEventRecoveryCodesRegen     = authevents.RecoveryCodesRegen
	AuthEventSessionRevoked         = authevents.SessionRevoked
	AuthEventTokenMinted            = authevents.TokenMinted
	AuthEventTokenRevoked           = authevents.TokenRevoked
	AuthEventOAuthLinked            = authevents.OAuthLinked
)

// AuthEvent is the PII-minimal record handed to Config.AuthEventSink. It carries a user id and a
// truncated IP prefix, never an email, name or token.
type AuthEvent = authevents.Event

// AuthEventSink receives every AuthEvent synchronously. Implementations must return quickly; panics
// are recovered.
type AuthEventSink = authevents.Sink

// AuthEventChannelSink returns an AuthEventSink that forwards to ch and drops events when ch is
// full (never blocks).
func AuthEventChannelSink(ch chan<- AuthEvent) AuthEventSink { return authevents.ChannelSink(ch) }

// RecordTokenMinted reports a token mint from an issuer (API tokens, device codes). kind is a short
// label such as "api"; it must never contain the token itself.
func (a *TheAuth) RecordTokenMinted(ctx context.Context, userID ULID, kind string) {
	a.EmitAudit(ctx, "token.minted", TargetRef{Type: "user", ID: userID.String()}, map[string]any{"kind": kind})
}

// RecordTokenRevoked is the revoke counterpart of RecordTokenMinted.
func (a *TheAuth) RecordTokenRevoked(ctx context.Context, userID ULID, kind string) {
	a.EmitAudit(ctx, "token.revoked", TargetRef{Type: "user", ID: userID.String()}, map[string]any{"kind": kind})
}

func (a *TheAuth) dispatchAuthEvent(ctx context.Context, action string, target TargetRef, metadata map[string]any) {
	if a.authEventSink == nil {
		return
	}
	md, hasMD := audit.MetadataFromContext(ctx)
	ctxUser := ""
	if u, ok := UserFromContext(ctx); ok && u != nil {
		ctxUser = u.ID.String()
	}
	if ev, ok := authevents.Build(action, target.Type, target.ID, metadata, md, hasMD, ctxUser); ok {
		authevents.Deliver(ctx, a.authEventSink, ev)
	}
}

// auditContextMiddleware attaches the client IP and user agent to the request context for audit events.
func (a *TheAuth) auditContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := audit.MetadataFromContext(r.Context()); !ok {
			ctx := audit.WithAuditMetadata(r.Context(), audit.AuditMetadata{
				IP:        extractClientIPTrusting(r, a.trustedProxies),
				UserAgent: r.UserAgent(),
			})
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// Severity ranks a doctor finding.
type Severity = doctor.Severity

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

const (
	DoctorSignupOpen         = doctor.DoctorSignupOpen
	DoctorBootstrapOff       = doctor.DoctorBootstrapOff
	DoctorTrustedProxies     = doctor.DoctorTrustedProxies
	DoctorSecureCookie       = doctor.DoctorSecureCookie
	DoctorCSRFDisabled       = doctor.DoctorCSRFDisabled
	DoctorThrottleDisabled   = doctor.DoctorThrottleDisabled
	DoctorThrottleLax        = doctor.DoctorThrottleLax
	DoctorPasswordMinLength  = doctor.DoctorPasswordMinLength
	DoctorPasswordNoBreach   = doctor.DoctorPasswordNoBreach
	DoctorAdminNoTOTP        = doctor.DoctorAdminNoTOTP
	DoctorNoSecondFactor     = doctor.DoctorNoSecondFactor
	DoctorSessionTTLLong     = doctor.DoctorSessionTTLLong
	DoctorSessionNoIdle      = doctor.DoctorSessionNoIdle
	DoctorTokenNoExpiry      = doctor.DoctorTokenNoExpiry
	DoctorTokenLongExpiry    = doctor.DoctorTokenLongExpiry
	DoctorTokenRoot          = doctor.DoctorTokenRoot
	DoctorAgentTokenLong     = doctor.DoctorAgentTokenLong
	DoctorTokensUnpruned     = doctor.DoctorTokensUnpruned
	DoctorSessionsUnpruned   = doctor.DoctorSessionsUnpruned
	DoctorEncryptionKey      = doctor.DoctorEncryptionKey
	DoctorAuditSink          = doctor.DoctorAuditSink
	DoctorWebAuthnRPID       = doctor.DoctorWebAuthnRPID
	DoctorRedirectAllowList  = doctor.DoctorRedirectAllowList
	DoctorCookieDomain       = doctor.DoctorCookieDomain
	DoctorCookieNoneOpen     = doctor.DoctorCookieNoneOpen
	DoctorSecurityHeadersOff = doctor.DoctorSecurityHeadersOff
)

// DoctorFindingIDs lists every finding ID a check can emit.
func DoctorFindingIDs() []string { return doctor.DoctorFindingIDs() }

// DoctorAdminLister is the optional storage capability that lets Doctor check second-factor
// coverage for admins.
type DoctorAdminLister interface {
	ListAdminUserIDs(ctx context.Context) ([]ULID, error)
}

// DoctorSessionCounter is the optional storage capability that counts expired but unpruned sessions.
type DoctorSessionCounter interface {
	CountExpiredSessions(ctx context.Context, before time.Time) (int, error)
}

// Doctor inspects the live Config and storage and reports security-posture findings, most serious
// first. It never mutates state and never includes secrets.
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
		SAMLTrackerMemory: cfg.SAML != nil && cfg.Stores.Cache == nil,
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
		CookieName:        cfg.CookieName,
		CookieDomain:      cfg.Cookies.Domain,
		CookieSameSite:    strings.ToLower(cfg.Cookies.SameSite),
		CookiePartitioned: cfg.Cookies.Partitioned,
		SecurityHeaders:   cfg.SecurityHeaders,
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

// mountDoctor serves GET /auth/admin/doctor to callers holding the root ability.
func (a *TheAuth) mountDoctor(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	r.With(ipLimit, a.RequireAbility(AbilityRoot)).Get("/admin/doctor", a.handleDoctor)
}

func (a *TheAuth) handleDoctor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(a.Doctor(r.Context()))
}
