package theauth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/authevents"
	"github.com/glincker/theauth-go/v2/internal/doctor"
	"github.com/glincker/theauth-go/v2/internal/observability"
	"github.com/go-chi/chi/v5"
)

// Observability re-exports are the public surface for plugging tracing +
// metrics adapters into TheAuth. The underlying types live in
// internal/observability so the implementation is auditable in one diff
// and downstream consumers never import an internal/ path.
//
// Design (locked 2026-06-21):
//
//   - Adapter pattern, NO hard dependency on OpenTelemetry, Prometheus, or
//     any other vendor. Consumers wire their own implementations.
//   - mcpresource/go.mod stays zero-dep; it never depends on this package.
//   - Cardinality discipline: high-cardinality identifiers (client_id,
//     user_id, IP) go on spans as attributes, NEVER on metric labels.
//
// See examples/observability-otel and examples/observability-prom for
// reference adapter implementations.

// Tracer is the span starter adapters implement. See
// internal/observability.Tracer for the full contract.
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

// Metrics is the instrument factory adapters implement. See
// internal/observability.Metrics for the full contract.
type Metrics = observability.Metrics

// Counter is a monotonic counter.
type Counter = observability.Counter

// Histogram is a distribution histogram.
type Histogram = observability.Histogram

// Gauge is a settable, incrementable, decrementable instantaneous value.
type Gauge = observability.Gauge

// Labels is the (name -> value) label set for a single metric instance.
// Cardinality discipline: callers MUST NOT put high-cardinality identifiers
// into Labels.
type Labels = observability.Labels

// Hooks bundles the consumer-supplied observability adapters. Attach to
// Config.Observability to wire tracing + metrics into TheAuth. Either
// field MAY be nil; the library falls back to no-op adapters per field.
type Hooks = observability.Hooks

// Status is the canonical span / metric status enum used across every
// instrumented operation in the library.
type Status = observability.Status

// Span / metric / attribute names re-exported so consumers building
// dashboards or alerts can reference them by symbol rather than by
// stringly-typed name.
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

// LatencyBuckets is the shared histogram bucket layout used by every
// _latency_seconds metric the library emits. Consumers pre-registering
// Prometheus histograms MUST use this exact slice so bucket boundaries
// align between library call sites and consumer registrations.
var LatencyBuckets = observability.LatencyBuckets

// coalesceHooks returns a non-nil *Hooks. The constructor uses this so
// every internal service can call hooks.StartSpan / hooks.Counter without
// nil-checking the pointer (the nil-safe helpers handle nil inner fields).
func coalesceHooks(h *Hooks) *Hooks {
	if h == nil {
		return &Hooks{}
	}
	return h
}

// Hooks returns the observability bundle in use. Returns a non-nil pointer
// even when no Observability was configured (the no-op bundle). Exposed so
// consumers writing custom services on top of theauth-go can share the
// same Tracer / Metrics adapters without re-wiring.
func (a *TheAuth) ObservabilityHooks() *Hooks {
	if a == nil {
		return &Hooks{}
	}
	return a.hooks
}

// DefaultRedactor masks values for keys named password, secret, token, code,
// refresh_token, access_token (case-insensitive) at any nesting depth.
func DefaultRedactor(metadata map[string]any) map[string]any { return audit.DefaultRedactor(metadata) }

// SeededSecretKeys returns a copy of the case-insensitive key blocklist
// applied by the default redactor.
func SeededSecretKeys() []string { return audit.SeededSecretKeys() }

// HashEmailForAudit returns sha256(lowercase(email)) hex-encoded.
func HashEmailForAudit(email string) string { return audit.HashEmailForAudit(email) }

// AuditSink streams audit events to an external SIEM or observability
// system. Implementations must be best-effort: a failed Stream call must
// never block writes to the canonical storage layer. Failures increment
// Stats.AuditSinkFailed.
//
// Built-in implementations live under audit/sinks/:
//
//   - audit/sinks/otlp: OTLP/HTTP logs exporter
//   - audit/sinks/splunkhec: Splunk HTTP Event Collector
//   - audit/sinks/webhook: generic CloudEvents 1.0 POST
type AuditSink interface {
	// Stream sends a batch of audit events to the external system.
	// Implementations should apply a reasonable timeout internally.
	// A non-nil error is logged and counted in Stats.AuditSinkFailed;
	// it does not affect storage writes.
	Stream(ctx context.Context, batch []AuditEvent) error

	// Name identifies the sink for logging and metrics labels.
	Name() string
}

// AuthEventType names one security-relevant authentication event.
type AuthEventType = authevents.Type

// The AuthEventType values emitted by the library. The strings are stable.
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

// AuthEvent is the PII-minimal record handed to Config.AuthEventSink. It
// carries a user id and a truncated IP prefix, never an email, name or token.
type AuthEvent = authevents.Event

// AuthEventSink receives every AuthEvent synchronously on the emitting
// goroutine. Implementations must return quickly and must not block; a
// panic is recovered and logged.
type AuthEventSink = authevents.Sink

// AuthEventChannelSink returns an AuthEventSink that forwards events to ch
// without ever blocking: when ch is full the event is dropped.
func AuthEventChannelSink(ch chan<- AuthEvent) AuthEventSink { return authevents.ChannelSink(ch) }

// RecordTokenMinted is the hook point for token issuers (API tokens, device
// codes, service tokens) to report a mint. kind is a short label such as
// "api" or "device"; it must not contain the token itself.
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

// auditContextMiddleware attaches the client IP and user agent to the
// request context so every audit event and AuthEvent carries them.
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
